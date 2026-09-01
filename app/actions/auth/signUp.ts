"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  signupSchema,
  signupComConviteSchema,
  type SignupInput,
  type SignupComConviteInput,
} from "@/lib/auth/schemas";
import { verifyInviteToken } from "@/lib/auth/invite-token";
import { decidirConviteDoSignup } from "@/lib/auth/convite-no-signup";
import { ensureTenantForUser } from "@/lib/auth/provision";
import { audit, hashEmail } from "@/lib/audit";
import { authRateLimited, AUTH_LIMITS } from "@/lib/auth/rate-limit";
import { env } from "@/lib/env";

export type SignUpResult =
  | { ok: true }
  | {
      ok: false;
      error:
        | "validation_error"
        | "rate_limited"
        | "signup_failed"
        | "email_taken"
        | "convite_invalido";
      details?: Record<string, unknown>;
    };

/**
 * Signup self-service SEM confirmação de e-mail.
 *
 * A confirmação por e-mail está DESATIVADA por decisão de produto: o link do
 * GoTrue não fecha de forma confiável nesta instalação (ver o comentário longo
 * em /auth/confirm sobre PKCE + cookie SameSite=strict) e a operação quer que a
 * conta funcione no ato do cadastro. Por isso a conta é criada JÁ CONFIRMADA
 * via Admin API (`email_confirm: true`), o tenant é provisionado na hora e a
 * sessão é estabelecida — o usuário cai direto no onboarding, sem caixa de
 * entrada no meio.
 *
 * Segurança: `email_confirm: true` só troca "provar posse do e-mail" por
 * "cadastro imediato". Todo o resto do modelo continua — rate limit por IP,
 * revalidação do convite pela assinatura HMAC + e-mail, provisionamento via
 * service role a partir do usuário recém-criado (nunca do body).
 */
export async function signUp(
  input: SignupInput | SignupComConviteInput,
  /**
   * Token de convite, quando a conta está sendo criada para ACEITAR um convite.
   * Revalidado no servidor: quem decide é `decidirConviteDoSignup`, comparando a
   * assinatura do token com o e-mail efetivamente cadastrado.
   */
  inviteToken?: string,
): Promise<SignUpResult> {
  const temConvite = typeof inviteToken === "string" && inviteToken.trim() !== "";
  const parsed = temConvite
    ? signupComConviteSchema.safeParse(input)
    : signupSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: "validation_error",
      details: parsed.error.flatten().fieldErrors,
    };
  }

  const hdrs = await headers();
  const requestId = hdrs.get("x-request-id");
  const ip = hdrs.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null;
  const userAgent = hdrs.get("user-agent") ?? null;

  // Criar conta é fluxo raro por pessoa: teto baixo por IP evita fábrica de
  // organizações (cada signup provisiona tenant). Issue #64.
  if (await authRateLimited("signup", null, AUTH_LIMITS.signup)) {
    return { ok: false, error: "rate_limited" };
  }

  // Só vira convite se o token verificar E for para este e-mail. Divergência
  // aqui não é erro do usuário — é tentativa de entrar em organização alheia
  // colando um token que chegou para outra pessoa.
  let convite: string | null = null;
  if (temConvite && inviteToken) {
    const payload = verifyInviteToken(inviteToken);
    if (!payload) {
      return { ok: false, error: "validation_error", details: { invite: ["convite_invalido"] } };
    }
    if (payload.email.trim().toLowerCase() !== parsed.data.email.trim().toLowerCase()) {
      return { ok: false, error: "validation_error", details: { invite: ["email_divergente"] } };
    }
    convite = inviteToken;
  }

  const email = parsed.data.email.trim().toLowerCase();

  // Conta criada JÁ CONFIRMADA. Metadata segue o mesmo canal de antes: convite
  // OU nome da empresa, consumido logo abaixo pelo provisionamento.
  const admin = createAdminClient();
  const { data: created, error: createError } = await admin.auth.admin.createUser({
    email,
    password: parsed.data.password,
    email_confirm: true,
    user_metadata: convite
      ? { invite_token: convite }
      : { org_name: (parsed.data as SignupInput).org_name },
  });

  if (createError || !created.user) {
    // GoTrue devolve 422 "already been registered" para e-mail existente.
    const jaCadastrado =
      createError?.status === 422 ||
      /already.*registered|already.*exists/i.test(createError?.message ?? "");
    await audit({
      action: "auth.signup_failed",
      metadata: {
        email_hash: hashEmail(email),
        reason: createError?.message ?? "no_user",
      },
      requestId,
      ip,
      userAgent,
    });
    return { ok: false, error: jaCadastrado ? "email_taken" : "signup_failed" };
  }

  const user = created.user;

  // Bifurcação convite vs. organização própria — mesma decisão de /auth/confirm,
  // agora sobre o usuário recém-criado. `user_metadata` não é autoridade: o
  // veredito vem da assinatura HMAC do token MAIS o e-mail confirmado.
  const decisao = decidirConviteDoSignup(user);
  if (decisao.tipo === "recusar") {
    // Falha FECHADA: havia convite e não vale. Desfaz o usuário para não deixar
    // conta órfã sem tenant nem convite aceito.
    await admin.auth.admin.deleteUser(user.id);
    await audit({
      action: "auth.signup_provision_recusado",
      actorUserId: user.id,
      metadata: { motivo: decisao.motivo },
      requestId,
      ip,
      userAgent,
    });
    return { ok: false, error: "convite_invalido" };
  }

  if (decisao.tipo === "provisionar") {
    try {
      await ensureTenantForUser(user);
    } catch (e) {
      await admin.auth.admin.deleteUser(user.id);
      await audit({
        action: "auth.signup_provision_failed",
        actorUserId: user.id,
        metadata: { reason: e instanceof Error ? e.message : String(e) },
        requestId,
        ip,
        userAgent,
      });
      return { ok: false, error: "signup_failed" };
    }
  }

  // Estabelece a sessão: sem confirmação por e-mail, a conta já é usável e o
  // usuário entra direto. Login server-side garante que os Set-Cookie do
  // GoTrue propaguem antes do middleware reavaliar a sessão.
  const supabase = await createClient();
  const { error: signInError } = await supabase.auth.signInWithPassword({
    email,
    password: parsed.data.password,
  });
  if (signInError) {
    // Conta criada e provisionada, mas a sessão falhou: manda para o login em
    // vez de travar. Não é caminho esperado.
    await audit({
      action: "auth.signup_signin_failed",
      actorUserId: user.id,
      metadata: { reason: signInError.message },
      requestId,
      ip,
      userAgent,
    });
    redirect("/login?signup=ok");
  }

  await audit({
    action: "auth.signup_confirmed",
    actorUserId: user.id,
    metadata: { autoconfirm: true },
    requestId,
    ip,
    userAgent,
  });

  // Convidado vai ao aceite (sessão já firmada); dono novo vai ao onboarding.
  redirect(decisao.tipo === "convite" ? `/team/accept-invite/${decisao.token}` : "/onboarding/welcome");
}
