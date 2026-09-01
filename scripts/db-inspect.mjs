import pg from "pg"

const { Client } = pg

const connectionString = process.env.POSTGRES_URL_NON_POOLING
if (!connectionString) {
  console.error("POSTGRES_URL_NON_POOLING não definido")
  process.exit(1)
}

const client = new Client({
  connectionString,
  ssl: { rejectUnauthorized: false },
})

async function main() {
  await client.connect()

  // Contagem de usuários auth
  const users = await client.query(
    `select id, email, email_confirmed_at, created_at from auth.users order by created_at`,
  )
  console.log("=== auth.users (" + users.rowCount + ") ===")
  for (const u of users.rows) {
    console.log(
      `${u.email} | confirmed=${u.email_confirmed_at ? "yes" : "no"} | ${u.id}`,
    )
  }

  // Tabelas tenant relevantes
  for (const t of [
    "organizations",
    "organization_members",
    "platform_admins",
    "profiles",
    "user_profiles",
  ]) {
    try {
      const r = await client.query(`select count(*)::int as n from public.${t}`)
      console.log(`public.${t}: ${r.rows[0].n} linhas`)
    } catch (e) {
      console.log(`public.${t}: (erro/inexistente) ${e.message}`)
    }
  }

  // Total de tabelas em public
  const tbls = await client.query(
    `select count(*)::int as n from information_schema.tables where table_schema='public' and table_type='BASE TABLE'`,
  )
  console.log("Total tabelas public: " + tbls.rows[0].n)

  await client.end()
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
