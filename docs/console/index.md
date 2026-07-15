# Visão geral do GateLite

O GateLite é um provedor de identidade e Single Sign-On baseado em OpenID Connect. Ele centraliza usuários, login, segundo fator, aplicações integradas e emissão de JWTs assinados com RSA.

## Conceitos principais

| Conceito | Uso no GateLite |
|---|---|
| **Usuário** | Identidade que entra com senha e, quando exigido, TOTP. |
| **Grupo** | Conjunto de usuários que compartilha roles de aplicações e permissões administrativas. |
| **Client** | Aplicação OIDC: SPA, mobile/desktop, backend web, serviço máquina a máquina ou API. |
| **Role** | Autorização pertencente a um client, emitida nos claims `roles` e `resource_access`. |
| **Scope** | Permissão solicitada ao protocolo, como `openid`, `profile`, `email`, `groups` e `offline_access`. |
| **Client secret** | Credencial de um client confidencial. Não é um access token. |
| **Permissão administrativa** | Autoriza ações no console do GateLite; não é enviada às aplicações. |

## Fluxo de acesso

```text
Usuário ──► Grupo ──► Role do client ──► JWT
   └──────── Role direta ───────────────► JWT
```

As roles são definidas na etapa **Roles** do próprio client. Depois, podem ser distribuídas no formulário de grupos ou diretamente no formulário de usuários. O caminho recomendado é usuário → grupo → role.

## Console

| Área | Conteúdo |
|---|---|
| **Visão geral** | Contadores, endpoint de descoberta e ações rápidas. |
| **Usuários** | Identidades, credenciais, grupos, roles diretas e permissões. |
| **Grupos** | Membros, roles compartilhadas e permissões administrativas. |
| **Clients** | Aplicações, protocolo, URLs, CORS, scopes, roles e client secrets. |
| **Configurações** | Cadastro, localização, SMTP, segurança, tokens, auditoria e atalhos administrativos. |
| **Auditoria** | Eventos, ator, alvo, data e IP de origem. |
| **Documentação** | Estas páginas. |

## Próximas leituras

- [Primeiros passos](primeiros-passos)
- [Usuários](usuarios) e [Grupos](grupos)
- [Clients](clients) e [Roles](roles)
- [Configurações](configuracoes) e [Auditoria](auditoria)
- [Integração OIDC](integracao)
