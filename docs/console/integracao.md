# Integração OIDC

Referência rápida para desenvolvedores integrando aplicações ao GateLite.

## Endpoints

| Endpoint | Método | Finalidade |
|---|---|---|
| `/.well-known/openid-configuration` | GET | Discovery — a fonte de verdade dos metadados |
| `/oidc/authorize/` | GET | Início do Authorization Code |
| `/oidc/token/` | POST | Troca de código, refresh e client credentials |
| `/oidc/userinfo/` | GET | Claims do usuário pelo Bearer token |
| `/oidc/jwks/` | GET | Chaves públicas RSA para validação local |
| `/oidc/revoke/` | POST | Revogação de access/refresh token |
| `/oidc/introspect/` | POST | Estado do token (client confidencial) |
| `/oidc/logout/` | GET | Logout iniciado pela aplicação |

Configure as bibliotecas OIDC apontando para o Discovery — endpoints, algoritmos e claims são descobertos automaticamente.

## SPA: Authorization Code + PKCE

```javascript
const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");

const verifier = base64url(crypto.getRandomValues(new Uint8Array(64)));
const challenge = base64url(await crypto.subtle.digest(
  "SHA-256", new TextEncoder().encode(verifier)));
sessionStorage.setItem("pkce_verifier", verifier);

const authorize = new URL("https://auth.example.com/oidc/authorize/");
authorize.search = new URLSearchParams({
  client_id: "portal-web",
  redirect_uri: "https://portal.example.com/callback",
  response_type: "code",
  scope: "openid profile email groups offline_access",
  audience: "portal-api",
  code_challenge: challenge,
  code_challenge_method: "S256",
  state: crypto.randomUUID(),
  nonce: crypto.randomUUID(),
});
location.assign(authorize);
```

No callback, troque o código (valide o `state` antes):

```javascript
const response = await fetch("https://auth.example.com/oidc/token/", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    client_id: "portal-web",
    code,
    redirect_uri: "https://portal.example.com/callback",
    code_verifier: sessionStorage.getItem("pkce_verifier"),
  }),
});
const tokens = await response.json();
```

O navegador nunca recebe client secret. Prefira access tokens em memória.

## Service account: Client Credentials

```bash
curl -u 'worker-service:CLIENT_SECRET' \
  -X POST 'https://auth.example.com/oidc/token/' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=jobs.read' \
  --data-urlencode 'audience=jobs-api'
```

O token sai com `sub: "client:worker-service"`, `amr: ["client_secret"]` e `acr: urn:gatelite:acr:client`.

## Validando o JWT na API (Python)

```python
import jwt

issuer = "https://auth.example.com"
jwks = jwt.PyJWKClient(f"{issuer}/oidc/jwks/")
signing_key = jwks.get_signing_key_from_jwt(token)

claims = jwt.decode(
    token, signing_key.key, algorithms=["RS256"],
    issuer=issuer, audience="portal-api",
)

if claims.get("token_use") != "access":
    raise PermissionError("Tipo de token inválido")

roles = set(claims.get("resource_access", {}).get("portal-api", {}).get("roles", []))
if "reader" not in roles:
    raise PermissionError("Role reader obrigatória")

# Para exigir segundo fator:
if claims.get("acr") != "urn:gatelite:acr:2":
    raise PermissionError("MFA obrigatório")
```

Valide **no mínimo** assinatura, algoritmo, `iss`, `exp`, `aud` e `token_use`. Use `azp` para restringir qual client pode chamar a API.

## Exemplo de payload

Access token emitido para o usuário `42` no cenário SPA acima — client `portal-web` pedindo a audience `portal-api`, após login com senha e segundo fator:

```json
{
  "iss": "https://auth.example.com",
  "sub": "42",
  "aud": "portal-api",
  "azp": "portal-web",
  "jti": "wJ4jRkD0m3H8vX2sLq9TzA1c",
  "iat": 1767100000,
  "exp": 1767100300,
  "scope": "openid profile email groups offline_access",
  "token_use": "access",
  "roles": ["reader", "editor"],
  "resource_access": { "portal-api": { "roles": ["reader", "editor"] } },
  "sid": "0b6c9f1e-4b7d-4a54-9d2c-8f5e6a7b3c21",
  "auth_time": 1767099980,
  "amr": ["pwd", "otp"],
  "acr": "urn:gatelite:acr:2"
}
```

O header traz `{"alg": "RS256", "kid": "..."}` — use o `kid` para escolher a chave no JWKS. No **ID token**, `token_use` é `"id"`, o `aud` é o próprio client (`portal-web`), as roles são as do client e entram os claims do usuário conforme os scopes:

```json
{
  "token_use": "id",
  "aud": "portal-web",
  "preferred_username": "ana.souza",
  "name": "Ana Souza",
  "given_name": "Ana",
  "family_name": "Souza",
  "locale": "pt-BR",
  "zoneinfo": "America/Sao_Paulo",
  "email": "ana.souza@example.com",
  "email_verified": true,
  "groups": ["financeiro"],
  "nonce": "b52c4a8e-..."
}
```

Em tokens de Client Credentials não há sessão: saem `sub: "client:worker-service"`, `amr: ["client_secret"]`, `acr: "urn:gatelite:acr:client"`, sem `sid` nem `auth_time`.

## Claims principais

| Claim | Conteúdo |
|---|---|
| `sub` | Usuário (`"42"`) ou service account (`"client:worker"`) |
| `aud` / `azp` | Audience (quem valida) / client que solicitou |
| `token_use` | `access` ou `id` |
| `roles` / `resource_access` | Roles efetivas para a audience |
| `groups` | Grupos relevantes para o client (scope `groups`) |
| `email` / `email_verified` | Verificado só se o endereço confirmado ainda é o atual |
| `locale` / `zoneinfo` | Idioma e fuso horário do usuário (scope `profile`) |
| `auth_time`, `amr`, `acr` | Quando e como o usuário autenticou (`["pwd","otp"]`, `acr:2` = com segundo fator) |
| `sid`, `jti` | Sessão OIDC e id único do token |

## Refresh tokens e revogação

- Refresh só é emitido com **Refresh habilitado no client** + scope `offline_access`.
- Cada uso rotaciona o token; reutilizar um antigo revoga a **família inteira** e encerra a sessão OIDC (proteção contra roubo).
- O refresh não pode ampliar os scopes originais.
- UserInfo e Introspection enxergam revogações imediatamente; validação JWT local só percebe no `exp` — mantenha TTLs curtos ou use Introspection quando revogação imediata for requisito.

## Erros comuns

| Erro | Causa provável |
|---|---|
| `redirect_uri inválido` | A URI enviada difere da cadastrada (inclusive barra final). |
| `invalid_target` | A audience pedida não está nas audiences permitidas do client. |
| `invalid_scope` | Scope não cadastrado no client, ou falta `openid` no Authorization Code. |
| PKCE inválido | `code_challenge_method` diferente de S256, ou `code_verifier` não confere. |
| Token sem as roles esperadas | Confira `aud`, o client dono da role, a atribuição e sua expiração. |
