# Clients OIDC

Um client representa uma aplicação integrada ao GateLite. Exige a permissão `Pode gerenciar clients e roles`.

## Escolhendo o tipo certo

| Aplicação | Tipo de aplicação | Tipo de client | Secret | Fluxo esperado |
|---|---|---|---:|---|
| SPA (React/Vue/Angular) | SPA | Público | Não | Authorization Code + PKCE S256 |
| Aplicativo nativo/mobile | Nativo | Público | Não | Authorization Code + PKCE S256 |
| Backend web tradicional | Web | Confidencial | Sim | Authorization Code |
| Serviço sem usuário (worker, job) | Service account | Confidencial | Sim | Client Credentials |
| API que valida tokens | Resource server | Confidencial | Sim | Validação JWT ou Introspection |

Regras aplicadas automaticamente: SPA e nativos **devem** ser públicos; services e resource servers **devem** ser confidenciais. Client público sempre usa `token_endpoint_auth_method=none`, exige PKCE e não pode habilitar Client Credentials.

## Campos do formulário

### Identificação

| Campo | O que significa |
|---|---|
| **Nome** | Nome de exibição no console. |
| **Client ID** | Identificador enviado pelos apps (`client_id`). Gerado automaticamente; aceita letras, números, ponto, hífen, underscore e til. |
| **Tipo de aplicação / Tipo de client** | Conforme a tabela acima. |
| **Ativo** | Client inativo não autentica ninguém e invalida as sessões OIDC associadas. |

### Protocolo

| Campo | O que significa |
|---|---|
| **Método de autenticação** | Como o client se autentica no token endpoint: `Basic` (header) ou `Post` (corpo). O método é exigido **exatamente** — um client Basic não pode mandar as credenciais no corpo. |
| **Authorization Code habilitado** | Fluxo de login de usuário. Desligue em service accounts puros. |
| **Refresh Token habilitado** | Permite renovar tokens. O refresh também exige o scope `offline_access` na autorização. |
| **Client Credentials habilitado** | Somente confidenciais. Permite obter token sem usuário (subject `client:<client_id>`). |
| **Exigir PKCE** | Sempre ligado em públicos. Pode ser exigido também em confidenciais. |
| **Exigir MFA** | Força step-up: o usuário precisa de sessão com segundo fator para receber tokens deste client, mesmo com política global `Opcional`. |
| **Scopes permitidos** | Separe por espaço, vírgula ou linha. Authorization Code exige `openid`. Scopes que não existirem são criados. |

### URLs

| Campo | Regras de validação |
|---|---|
| **Redirect URIs** | Uma por linha, correspondência **exata** (scheme, host, porta, path e barra final). Sem fragmentos ou credenciais embutidas. HTTP só para `localhost`, `127.0.0.1` e `::1`. Schemes customizados (`myapp://callback`) só para aplicativos nativos. |
| **Post logout redirect URIs** | Mesmas regras; usadas pelo `end_session_endpoint`. |
| **Web origins (CORS)** | Somente scheme, host e porta (sem path/query). Liberam o navegador a chamar token, userinfo, revoke e JWKS. |

### Acesso

| Campo | O que significa |
|---|---|
| **Política de acesso** | `Aberto`: qualquer usuário ativo autentica. `Restrito`: exige role atribuída (direta, por grupo, padrão) **ou** constar nas exceções abaixo. |
| **Grupos/Usuários autorizados** | Exceções da política restrita: entram mesmo sem role. |
| **Audiences permitidas** | Resource servers que este client pode pedir no parâmetro `audience`. Sem isso, o token sai com `aud` do próprio client e a API deve rejeitá-lo. |
| **Gerar novo secret** | Em confidenciais. O secret é exibido **uma única vez** após salvar — copie na hora. O banco guarda apenas o hash. |

## Tutorial: SPA + API

1. **Crie a API** (`portal-api`): tipo Resource server, confidencial, desmarque Authorization Code, scopes `api.read api.write`.
2. **Crie as roles** `reader` e `editor` dentro de `portal-api` — veja [Roles](roles).
3. **Crie a SPA** (`portal-web`): tipo SPA, público, Authorization Code + Refresh habilitados, scopes `openid profile email groups offline_access`, Redirect URI `https://portal.example.com/callback`, Web origin `https://portal.example.com`, e `portal-api` nas audiences permitidas.
4. No frontend, inicie o fluxo com `audience=portal-api` — o access token sairá com `aud: portal-api` e as roles do usuário naquela API. Exemplo de código em [Integração OIDC](integracao).

## Secrets e rotação

- Ao gerar um novo secret, o anterior continua válido durante a **sobreposição** configurada na política de segurança, permitindo troca sem downtime.
- Um client que virar público tem todos os secrets revogados automaticamente.
- Secret nunca aparece de novo: se perdeu, gere outro.

## Exigir MFA por client

Marque **Exigir MFA** no client (ou no resource server usado como audience) para exigir segundo fator naquela aplicação. No `/oidc/authorize/`, o GateLite faz o step-up antes de emitir o código, e os tokens saem com `amr`/`acr` refletindo a autenticação real (`acr: urn:gatelite:acr:2`). A API pode (e deve) validar o `acr` — exemplo em [Integração OIDC](integracao).
