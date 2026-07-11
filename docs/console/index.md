# Visão geral do GateLite

O GateLite é um provedor de identidade e Single Sign-On construído sobre OpenID Connect. Ele centraliza o login dos usuários, emite JWTs assinados com RSA e controla o que cada aplicação recebe em termos de identidade e autorização. O modelo lembra o Keycloak, mas com um único domínio de identidade: não existem realms nem multi-tenancy.

## Conceitos fundamentais

| Conceito | O que é |
|---|---|
| **Usuário** | Uma identidade que faz login com senha (e opcionalmente TOTP). Acumula acessos por grupos e atribuições diretas. |
| **Grupo** | Conjunto de usuários. Membros herdam automaticamente as roles de clients e as permissões administrativas vinculadas ao grupo. |
| **Client** | Uma aplicação integrada via OIDC: SPA, aplicativo nativo, backend web, service account ou resource server (API). |
| **Role** | Autorização que pertence a exatamente um client e é emitida no JWT (claims `roles` e `resource_access`). O mesmo nome pode existir em clients diferentes sem conflito. |
| **Scope** | Conjunto de claims que o client pode solicitar (`openid`, `profile`, `email`, `groups`, `offline_access`, ou scopes customizados). |
| **Audience** | O destinatário do access token (claim `aud`) — tipicamente a API que vai validá-lo. Um client só solicita audiences autorizadas para ele. |
| **Service account** | Um client confidencial que autentica sozinho via Client Credentials, sem usuário. Recebe roles próprias. |
| **Permissão administrativa** | Controla o próprio GateLite (acesso ao console, gerenciar usuários, chaves etc.). **Não** é enviada às aplicações — é diferente de role. |

## Como o acesso funciona

```text
Usuário ──┬── atribuição direta ────────┐
          └── membro de Grupo ── role ──┼──▶ Roles efetivas do Client
                    roles padrão ───────┤         │
                    roles compostas ────┘         ▼
                                          JWT: roles / resource_access
```

As roles efetivas são a união deduplicada das atribuições diretas, das herdadas por grupos, das roles padrão do client e das incluídas por composição. A role sempre pertence ao seu client e só é emitida para a audience correspondente.

## Mapa da documentação

- **[Primeiros passos](primeiros-passos)** — a ordem recomendada para configurar um ambiente novo.
- **[Usuários](usuarios)** — criar e editar usuários, cada campo explicado, e-mail e bloqueios.
- **[Grupos](grupos)** — organizar acessos compartilhados e permissões do console.
- **[Clients](clients)** — cadastrar aplicações: tipos, fluxos, URLs, scopes, audiences e secrets.
- **[Roles](roles)** — autorizações por client: padrão, compostas e atribuições com expiração.
- **[Configurações](configuracoes)** — cada item da política de segurança, tokens e chaves.
- **[Integração OIDC](integracao)** — endpoints, exemplos de código e validação de JWT.

## Onde cada coisa fica no console

| Menu | Conteúdo |
|---|---|
| Visão geral | Contadores, endpoint de descoberta e ações rápidas |
| Usuários / Grupos / Clients | Listagens com busca, filtros e formulários |
| Configurações | Política de segurança global, permissões, roles e chaves |
| Documentação | Estas páginas |

O acesso a cada menu depende das permissões administrativas do operador — veja a tabela completa em [Usuários](usuarios).
