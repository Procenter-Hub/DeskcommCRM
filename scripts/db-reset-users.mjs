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

  // Limpa tenants + vínculos primeiro (não há FK cascata de auth.users -> org).
  // Ordem: dependências antes das tabelas-pai.
  const steps = [
    "delete from public.user_organizations",
    "delete from public.platform_admins",
    "delete from public.organizations",
    "delete from auth.users",
  ]

  for (const sql of steps) {
    try {
      const r = await client.query(sql)
      console.log(`${sql} -> ${r.rowCount} linha(s)`)
    } catch (e) {
      console.log(`${sql} -> ERRO: ${e.message}`)
    }
  }

  // Confirmação
  const u = await client.query("select count(*)::int n from auth.users")
  const o = await client.query("select count(*)::int n from public.organizations")
  console.log(`\nRestante: auth.users=${u.rows[0].n}, organizations=${o.rows[0].n}`)

  await client.end()
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
