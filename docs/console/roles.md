# Roles por client

Roles são as autorizações que as aplicações leem no JWT. Cada role pertence a **exatamente um client** — `finance-api · reader` e `support-api · reader` são roles diferentes e não conflitam. Gerencie em **Clients → Roles** ou em **Configurações → Roles dos clients** (permissão `Pode gerenciar clients e roles`).

## Campos do formulário

| Campo | O que significa |
|---|---|
| **Client** | Dono da role. A role só é emitida em tokens cuja audience é este client. |
| **Nome** | Slug emitido no claim `roles` e em `resource_access.<client>.roles`. Único dentro do client. |
| **Descrição** | Texto livre para operadores. |
| **Role padrão** | Concedida automaticamente a todo usuário **com acesso ao client** (não a todos os usuários do GateLite). Útil para um nível básico, ex.: `viewer`. |
| **Grupos** | Todos os membros herdam a role. O caminho recomendado. |
| **Usuários diretos** | Exceções individuais. |
| **Service accounts** | Clients confidenciais que recebem esta role em tokens de Client Credentials. |
| **Roles compostas** | Outras roles **do mesmo client** incluídas automaticamente. Ex.: `admin` compõe `editor` que compõe `reader`. Ciclos são bloqueados na validação. |

## Atribuições: responsável e expiração

Cada vínculo (usuário, grupo ou service account) registra **quem atribuiu** e aceita uma **data de expiração** opcional. Uma atribuição expirada simplesmente deixa de ser emitida nos próximos tokens — ótima para acessos temporários (consultorias, plantões). A expiração também é respeitada na política de acesso restrito do client.

## Como as roles chegam na API

Um access token com `aud: portal-api` para um usuário com `editor` (direta) e `reader` (herdada por composição) contém:

```json
{
  "aud": "portal-api",
  "roles": ["editor", "reader"],
  "resource_access": {
    "portal-api": { "roles": ["editor", "reader"] }
  }
}
```

Na API, valide sempre o conjunto completo: assinatura, `iss`, `exp`, `aud` **e então** as roles em `resource_access.<sua-api>.roles`. Nunca autorize apenas pela existência de um nome de role sem checar a audience — o mesmo nome pode existir em outro client. Exemplos de código em [Integração OIDC](integracao).

## Resolução das roles efetivas

Para um usuário em um client, o GateLite emite a união deduplicada de:

1. roles atribuídas diretamente (não expiradas);
2. roles herdadas dos grupos (não expiradas);
3. roles padrão do client;
4. fecho transitivo das roles compostas dos itens anteriores.

Superusuários têm acesso administrativo ao GateLite, mas **não** ganham roles automaticamente — a API continua decidindo pela claim do token.
