# Changelog

Todas as mudanças relevantes deste projeto são documentadas neste arquivo.
O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o versionamento segue [SemVer](https://semver.org/lang/pt-BR/).

## [1.0.1] - 2026-07-11

### Adicionado

- Seção **Documentação** no console: páginas Markdown versionadas em `docs/console/` com visão geral do sistema, primeiros passos e tutoriais completos de usuários, grupos, clients, roles, configurações e integração OIDC.
- Realce de sintaxe (Pygments) nos blocos de código da documentação, em tema claro, e tabelas em estilo de linhas com zebra ocupando toda a largura do painel.

## [1.0.0] - 2026-07-11

Primeira versão estável do GateLite: provedor de identidade e SSO OpenID Connect com console administrativo próprio.

### Protocolo OIDC

- Discovery, JWKS, Authorization Code com PKCE S256, Refresh Token com rotação e detecção de replay por família, Client Credentials, UserInfo, Revogação, Introspection e RP-Initiated Logout.
- Clients públicos e confidenciais; audiences explícitas; roles isoladas por client com composição, herança por grupos, roles padrão e service accounts.
- JWTs RS256 com claims `auth_time`, `amr`, `acr`, `sid`, `roles` e `resource_access`; chaves privadas cifradas com AES-GCM no banco e rotação com janela de retenção no JWKS (verificação interna limitada à mesma janela).

### Autenticação e conta

- TOTP/2FA com QR Code, recovery codes de uso único, step-up por client e políticas `optional`/`admins`/`all`.
- Bloqueio temporário configurável após erros consecutivos de senha no login.
- Confirmação de e-mail por link de uso único e recuperação de senha somente para e-mail confirmado, ambas com reenvio limitado e sem enumeração de contas.
- Autosserviço: edição de perfil com username imutável, sessões OIDC visíveis e revogáveis pelo usuário.

### Console administrativo

- Gestão de usuários, grupos, clients, roles, permissões administrativas e chaves de assinatura, com RBAC granular e auditoria de operações.
- Política de segurança persistida no banco e editável no console: regras de senha, TTLs de tokens/sessão, sobreposição de secrets, validades de e-mail/recuperação e proteção contra força bruta.
- Formulários com listas de seleção por checkbox, filtro e contador; wizard em etapas.

### Implantação

- PostgreSQL via variáveis `DB_*` no ambiente (SQLite como padrão de desenvolvimento; testes sempre em SQLite).
- Dockerfile com Gunicorn, `collectstatic` no build, usuário sem privilégios e migrations automáticas na inicialização.
- Suporte a proxy TLS via `TRUST_PROXY_SSL_HEADER`.
- 85 testes automatizados cobrindo protocolo, segurança, RBAC, MFA, contas e interface.

[1.0.1]: https://github.com/alexandrekaspary/Gate-Lite/releases/tag/v1.0.1
[1.0.0]: https://github.com/alexandrekaspary/Gate-Lite/releases/tag/v1.0.0
