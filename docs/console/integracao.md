# Integração OpenID Connect

Use o endpoint de descoberta como fonte dos URLs e recursos do ambiente:

```text
https://auth.exemplo.com/.well-known/openid-configuration
```

## Endpoints principais

| Endpoint | Uso |
|---|---|
| `/.well-known/openid-configuration` | Metadados OIDC. |
| `/oidc/authorize/` | Login e emissão do Authorization Code. |
| `/oidc/token/` | Troca de code, refresh e Client Credentials. |
| `/oidc/userinfo/` | Claims do usuário autenticado. |
| `/oidc/jwks/` | Chaves públicas RSA. |
| `/oidc/revoke/` | Revogação de refresh/access token. |
| `/oidc/introspect/` | Estado atual de um token. |
| `/oidc/logout/` | Encerramento OIDC. |

## Escolher o fluxo

| Aplicação | Fluxo |
|---|---|
| SPA ou mobile/desktop | Authorization Code + PKCE S256, sem secret. |
| Backend web com login | Authorization Code + PKCE, autenticando no token endpoint com Client Secret Basic. |
| Serviço sem usuário | Client Credentials com Client Secret Basic. |
| API | Recebe e valida access tokens; não inicia login. |

O wizard do client preenche essas opções automaticamente.

## Authorization Code com PKCE

Gere um `code_verifier` aleatório e envie seu SHA-256 em base64url como `code_challenge`:

```text
GET /oidc/authorize/?
  client_id=portal-web&
  redirect_uri=https%3A%2F%2Fportal.exemplo.com%2Fcallback&
  response_type=code&
  scope=openid%20profile%20email%20groups%20offline_access&
  state=valor-aleatorio&
  nonce=valor-aleatorio&
  code_challenge=DESAFIO&
  code_challenge_method=S256
```

Depois do callback, troque o code:

```bash
curl -X POST https://auth.exemplo.com/oidc/token/ \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=portal-web' \
  -d 'code=CODIGO' \
  -d 'redirect_uri=https://portal.exemplo.com/callback' \
  -d 'code_verifier=VERIFICADOR'
```

Um backend confidencial também envia `Authorization: Basic base64(client_id:client_secret)`.

Sempre valide `state`; valide `nonce` no ID token. Redirect URI precisa coincidir exatamente com o cadastro.

## Client Credentials

```bash
curl -X POST https://auth.exemplo.com/oidc/token/ \
  -u 'worker-service:CLIENT_SECRET' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=api.read'
```

O token não representa usuário: `sub` começa com `client:` e `amr` contém `client_secret`.

## Refresh Token

Refresh só é emitido quando o client habilita o fluxo e a autorização solicita `offline_access`:

```bash
curl -X POST https://auth.exemplo.com/oidc/token/ \
  -d 'grant_type=refresh_token' \
  -d 'client_id=portal-web' \
  -d 'refresh_token=REFRESH_TOKEN'
```

Cada uso rotaciona o refresh. Reutilizar um valor antigo revoga a família inteira.

## Validar access tokens

Uma API deve verificar:

1. assinatura RS256 usando o `kid` e o JWKS;
2. algoritmo esperado;
3. `iss` igual ao issuer configurado;
4. `exp` e demais tempos;
5. `aud` igual ao client esperado pela API;
6. `token_use` igual a `access`;
7. roles necessárias.

Exemplo com PyJWT:

```python
import jwt

jwks = jwt.PyJWKClient("https://auth.exemplo.com/oidc/jwks/")
key = jwks.get_signing_key_from_jwt(token).key
claims = jwt.decode(
    token,
    key,
    algorithms=["RS256"],
    issuer="https://auth.exemplo.com",
    audience="portal-web",
)

if claims.get("token_use") != "access":
    raise PermissionError("Tipo de token inválido")
if "reader" not in claims.get("roles", []):
    raise PermissionError("Role reader obrigatória")
```

Se o client exige 2FA, a API também pode conferir `acr == "urn:gatelite:acr:2"`.

## Claims relevantes

| Claim | Conteúdo |
|---|---|
| `sub` | ID do usuário ou `client:<client_id>`. |
| `aud` | Client destinatário do token. |
| `azp` | Client que iniciou a solicitação. |
| `roles` | Roles efetivas para o destinatário. |
| `resource_access` | Roles agrupadas pelo client. |
| `scope` | Scopes concedidos. |
| `amr` / `acr` | Método e nível de autenticação. |
| `sid` / `jti` | Sessão e identificador único do token. |

## CORS

Cadastre em **Web origins (CORS)** somente origens exatas, como `https://portal.exemplo.com`. O GateLite libera os endpoints OIDC apenas quando a origem e o client da requisição correspondem ao cadastro.

## Revogação

UserInfo e Introspection percebem revogações imediatamente. Uma API que valida JWT localmente só percebe a expiração; use access tokens curtos ou Introspection quando o corte imediato for obrigatório.
