# GateLite

GateLite é um provedor de identidade e Single Sign-On construído com Django. Ele segue OpenID Connect, emite JWTs assinados com RSA, publica JWKS e oferece um console próprio para administrar usuários, grupos, clients e roles.

O modelo lembra o Keycloak, mas usa um único domínio de identidade: não existem realms ou uma camada de multi-tenancy.

## Conteúdo

- [Recursos](#recursos)
- [Arquitetura](#arquitetura)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Docker](#docker)
- [Primeiro acesso](#primeiro-acesso)
- [Usuários, grupos e roles](#usuários-grupos-e-roles)
- [Clients OIDC](#clients-oidc)
- [Integração React com uma API](#integração-react-com-uma-api)
- [Client Credentials](#client-credentials)
- [JWT, claims e validação](#jwt-claims-e-validação)
- [Autenticação em duas etapas](#autenticação-em-duas-etapas)
- [Endpoints](#endpoints)
- [Chaves e rotação](#chaves-e-rotação)
- [Operação e produção](#operação-e-produção)
- [Testes automatizados](#testes-automatizados)
- [Solução de problemas](#solução-de-problemas)
- [Licença](#licença)

## Recursos

- OpenID Connect Discovery e JWKS.
- Authorization Code com PKCE S256.
- Refresh Token com rotação, famílias e detecção de reutilização.
- Client Credentials para aplicações não interativas.
- Clients públicos e confidenciais.
- Aplicações SPA, nativas, web backend, service accounts e resource servers.
- Audience explícita para o fluxo frontend → API.
- Roles isoladas por client.
- Roles diretas, herdadas por grupos, padrão e compostas.
- Roles para service accounts.
- Atribuições com responsável, data e expiração opcional.
- Política de acesso aberta ou restrita por client.
- TOTP/2FA, QR Code, recovery codes e step-up por client.
- Edição do perfil com username imutável no autosserviço.
- Confirmação de e-mail por link temporário e de uso único.
- Recuperação de senha somente por e-mail confirmado, com reenvio limitado.
- Bloqueio temporário configurável após erros consecutivos de senha no login.
- Claims OIDC `auth_time`, `amr` e `acr`.
- Chaves RSA privadas cifradas no banco; nenhum arquivo de chave privada.
- Rotação de client secrets e de chaves de assinatura.
- Console administrativo responsivo em escala de cinza.
- Auditoria de autenticação e operações administrativas.
- Políticas configuráveis de senha, tokens e sessão SSO.

## Arquitetura

```text
Navegador / SPA / Backend
          │
          │ OpenID Connect
          ▼
┌──────────────────────────────┐
│ GateLite                     │
│                              │
│ Login + TOTP                 │
│ Authorization Server        │
│ Emissão JWT RS256            │
│ Console administrativo      │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Banco de dados               │
│                              │
│ Usuários / grupos            │
│ Clients / roles / scopes     │
│ Sessões / códigos / tokens   │
│ Secrets e chaves cifradas    │
│ Auditoria                    │
└──────────────────────────────┘
```

Não há configuração sensível de clients ou roles em arquivos. O estado funcional é persistido por models e migrations do Django.

### Modelo de autorização

```text
OIDCClient
├── Redirect URIs e post-logout URIs
├── Web Origins exatas
├── Scopes permitidos
├── Audiences autorizadas
├── Política de acesso
├── Client Roles
│   ├── usuários diretos
│   ├── grupos
│   ├── service accounts
│   ├── roles padrão
│   └── roles compostas
└── Client Secrets rotativos

Grupo
├── usuários membros
├── permissões administrativas
└── roles de qualquer client
```

As roles efetivas são a união deduplicada das atribuições diretas, das atribuições dos grupos, das roles padrão e das roles incluídas por composição. A role continua pertencendo ao seu client e só é emitida para a audience correspondente.

## Instalação

### Requisitos

- Python 3.12 ou 3.13.
- SQLite (padrão, desenvolvimento) ou PostgreSQL (recomendado em produção).
- HTTPS em produção.

### Ambiente local

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python manage.py migrate
venv/bin/python manage.py createsuperuser
venv/bin/python manage.py runserver
```

Acesse:

- Console: `http://localhost:8000/`
- Conta do usuário: `http://localhost:8000/account/`
- Django Admin: `http://localhost:8000/admin/`
- Discovery: `http://localhost:8000/.well-known/openid-configuration`

O Django Admin usa o mesmo fluxo de login e 2FA do GateLite; ele não constitui um caminho alternativo somente com senha.

## Configuração

O Django lê variáveis do ambiente do processo. O arquivo [.env.example](.env.example) serve como referência; ele não é carregado automaticamente por uma biblioteca `dotenv`.

| Variável | Obrigatória em produção | Finalidade |
|---|---:|---|
| `DJANGO_SECRET_KEY` | Sim | Assinaturas internas do Django |
| `KEY_ENCRYPTION_SECRET` | Sim | Derivação da chave AES-GCM que protege material sensível |
| `DJANGO_DEBUG` | Não | `1` em desenvolvimento; use `0` em produção |
| `DJANGO_ALLOWED_HOSTS` | Sim | Hosts separados por vírgula |
| `CSRF_TRUSTED_ORIGINS` | Conforme implantação | Origens HTTPS separadas por vírgula |
| `OIDC_ISSUER` | Sim | URL pública e estável do emissor, sem barra final |
| `TRUST_PROXY_SSL_HEADER` | Atrás de proxy TLS | `1` faz o Django confiar em `X-Forwarded-Proto: https`; ative somente se o proxy sempre definir o header |
| `DB_ENGINE` | Recomendado | `sqlite` (padrão) ou `postgres` |
| `DB_NAME` | Com Postgres | Nome do banco; padrão `gatelite` |
| `DB_USER` | Com Postgres | Usuário do banco; padrão `gatelite` |
| `DB_PASSWORD` | Com Postgres | Senha do usuário do banco |
| `DB_HOST` | Com Postgres | Host do banco; padrão `localhost` |
| `DB_PORT` | Com Postgres | Porta do banco; padrão `5432` |
| `EMAIL_HOST` / `EMAIL_PORT` | Sim para SMTP | Servidor e porta de e-mail transacional |
| `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD` | Conforme SMTP | Credenciais do provedor |
| `DEFAULT_FROM_EMAIL` | Recomendado | Remetente das confirmações e recuperações |

Com `DJANGO_DEBUG=0`, HTTPS obrigatório, cookies seguros e HSTS já são aplicados por padrão; as variáveis `DJANGO_SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`, `EMAIL_BACKEND`, `EMAIL_USE_TLS`, `EMAIL_USE_SSL`, `EMAIL_TIMEOUT` e `DB_CONN_MAX_AGE` existem apenas para sobrescrever esses padrões quando necessário.

As validades da confirmação de e-mail, do reenvio e da recuperação de senha não são variáveis de ambiente: elas ficam persistidas no banco junto com a política de segurança e são editadas no console em **Configurações → E-mail e recuperação de senha**. O mesmo vale para o bloqueio por força bruta no login (tentativas máximas e duração), em **Configurações → Proteção contra força bruta**.

Exemplo para um shell local:

```bash
cp .env.example .env
set -a
source .env
set +a
venv/bin/python manage.py runserver
```

Gere valores independentes e longos para `DJANGO_SECRET_KEY` e `KEY_ENCRYPTION_SECRET`:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(64))'
```

Não altere `KEY_ENCRYPTION_SECRET` em um ambiente existente sem um processo de recriptografia. A troca direta torna ilegíveis as chaves privadas RSA e os secrets TOTP já persistidos.

### Banco e migrations

Por padrão o banco local fica em `db.sqlite3`. Toda alteração de schema é versionada em `identity/migrations/`.

```bash
venv/bin/python manage.py migrate
venv/bin/python manage.py showmigrations identity
venv/bin/python manage.py makemigrations --check --dry-run --noinput
```

Para PostgreSQL, defina no ambiente (uma variável por linha no `.env`, sem string única de conexão):

```bash
DB_ENGINE=postgres
DB_NAME=gatelite
DB_USER=gatelite
DB_PASSWORD=senha-do-banco
DB_HOST=localhost
DB_PORT=5432
```

Com `DB_ENGINE=sqlite` (ou ausente), as variáveis `DB_*` restantes são ignoradas. A suíte de testes sempre usa SQLite, mesmo com `DB_ENGINE=postgres` configurado. Não reutilize SQLite para uma instalação concorrente de produção.

## Docker

O [Dockerfile](Dockerfile) constrói uma imagem com Gunicorn e executa `collectstatic` durante o build. Na inicialização, o entrypoint aplica as migrations pendentes antes de aceitar tráfego.

```bash
docker build -t gatelite .
docker run --rm -p 8000:8000 --env-file .env gatelite
```

Observações:

- Preencha o `.env` a partir de [.env.example](.env.example), com `DB_ENGINE=postgres` apontando para um PostgreSQL acessível pelo container (use `DB_HOST=host.docker.internal` ou o nome do serviço na sua rede Docker).
- Os arquivos estáticos são coletados em `/app/staticfiles`; sirva-os por proxy reverso ou CDN, conforme o [checklist de produção](#operação-e-produção).
- O container roda como usuário sem privilégios (`gatelite`).

## Primeiro acesso

1. Execute as migrations.
2. Crie um superusuário com `createsuperuser`.
3. Entre em `/`.
4. Abra **Configurações** e ajuste senha, MFA, duração de tokens e sessão.
5. Cadastre os clients.
6. Crie roles dentro de cada client.
7. Crie grupos, associe usuários e vincule as roles dos clients.
8. Confirme o endereço de e-mail enviado ao usuário.

Usuários novos recebem automaticamente apenas as permissões básicas para visualizar a própria conta e alterar a própria senha. Permissões administrativas e roles de aplicações são apresentadas e gerenciadas separadamente.

Endereços existentes antes da migration `0014` começam como não confirmados, pois não havia prova anterior de posse. O usuário pode solicitar a confirmação em **Minha conta → Editar dados**.

## Usuários, grupos e roles

### Permissões administrativas

As permissões administrativas controlam o próprio GateLite:

- acesso ao console;
- usuários;
- grupos;
- clients e roles;
- políticas de segurança;
- chaves;
- permissões administrativas.

Elas não são enviadas como roles globais para todas as aplicações.

### Perfil e e-mail confirmado

No autosserviço, o usuário pode alterar nome, sobrenome e e-mail. O username é apenas exibido e nunca faz parte do formulário editável.

Ao solicitar um endereço diferente:

1. nome e sobrenome são salvos imediatamente;
2. o e-mail atual permanece ativo;
3. o novo endereço fica pendente;
4. GateLite envia uma mensagem texto e HTML;
5. o link abre uma tela de revisão e só é consumido por um POST com CSRF;
6. após a confirmação, o novo endereço é ativado e as sessões existentes são revogadas.

O token bruto existe somente na mensagem enviada. O banco armazena seu hash SHA-256, expiração e controle de reenvio. A claim OIDC `email_verified` só é verdadeira quando o endereço confirmado ainda corresponde ao `User.email` atual.

### Roles dos clients

Cada role pertence a exatamente um client. O mesmo nome pode existir em clients diferentes sem criar conflito, por exemplo:

```text
finance-api · reader
support-api · reader
```

Uma role pode ser concedida:

- diretamente ao usuário;
- a um grupo, sendo herdada por todos os membros;
- como role padrão;
- a uma service account;
- como parte de uma role composta do mesmo client.

O caminho recomendado para acessos compartilhados é:

```text
Usuário → Grupo → Role do client
```

Use atribuições diretas para exceções individuais.

### Acesso aberto e restrito

- `open`: qualquer usuário ativo pode autenticar no client.
- `restricted`: o usuário precisa de atribuição de role, autorização direta ou pertencer a um grupo autorizado.

Superusuários têm acesso administrativo, mas a API ainda deve validar audience e roles do token.

## Clients OIDC

| Aplicação | Tipo | Secret | Fluxo esperado |
|---|---|---:|---|
| SPA React/Vue/Angular | Público | Não | Authorization Code + PKCE S256 |
| Aplicativo nativo | Público | Não | Authorization Code + PKCE S256 |
| Web backend | Confidencial | Sim | Authorization Code |
| Service account | Confidencial | Sim | Client Credentials |
| Resource server/API | Confidencial | Sim | Validação JWT ou Introspection |

Clients públicos sempre usam `token_endpoint_auth_method=none`, exigem PKCE e não podem habilitar Client Credentials. SPA e aplicações nativas devem ser públicas. Services e resource servers devem ser confidenciais.

### Redirect URIs e CORS

- Redirect URIs usam correspondência exata.
- Fragmentos e credenciais embutidas não são aceitos.
- HTTP é permitido somente para `localhost`, `127.0.0.1` e `::1`.
- Schemes customizados são aceitos apenas para aplicações nativas.
- Web Origins contêm somente scheme, host e porta, sem path ou query.

### Client secrets

O secret de um client confidencial é exibido uma única vez. O banco guarda apenas um hash adaptativo. Ao rotacionar, o secret anterior pode continuar válido durante o período de sobreposição configurado na política de segurança.

## Integração React com uma API

Considere:

- `portal-web`: SPA pública;
- `portal-api`: resource server confidencial;
- `portal-api` incluída nas audiences permitidas de `portal-web`;
- roles `reader` e `editor` criadas em `portal-api`.

Cadastre no `portal-web`:

```text
Redirect URI: https://portal.example.com/callback
Web Origin:   https://portal.example.com
Scopes:       openid profile email groups offline_access
Audience:     portal-api
```

### Criar o desafio PKCE

```javascript
const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replaceAll("+", "-")
  .replaceAll("/", "_")
  .replaceAll("=", "");

const verifierBytes = crypto.getRandomValues(new Uint8Array(64));
const verifier = base64url(verifierBytes);
const digest = await crypto.subtle.digest(
  "SHA-256",
  new TextEncoder().encode(verifier),
);
const challenge = base64url(digest);

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

Em produção, associe `state` à sessão e valide-o no callback.

### Trocar o código por tokens

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

if (!response.ok) throw new Error("Falha na troca do authorization code");
const tokens = await response.json();
```

O navegador nunca deve receber ou armazenar um client secret. Para aplicações públicas, prefira manter access tokens em memória e trate refresh tokens de acordo com o modelo de risco da aplicação.

## Client Credentials

Habilite Client Credentials no client confidencial, autorize a audience e conceda roles da API à service account.

```bash
curl -u 'worker-service:CLIENT_SECRET' \
  -X POST 'https://auth.example.com/oidc/token/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=jobs.read' \
  --data-urlencode 'audience=jobs-api'
```

O token usa um subject no formato `client:worker-service` e inclui:

```json
{
  "amr": ["client_secret"],
  "acr": "urn:gatelite:acr:client"
}
```

## JWT, claims e validação

Um access token de usuário pode conter:

```json
{
  "iss": "https://auth.example.com",
  "sub": "42",
  "aud": "portal-api",
  "azp": "portal-web",
  "scope": "openid profile email groups",
  "email": "user@example.com",
  "email_verified": true,
  "token_use": "access",
  "auth_time": 1760000000,
  "amr": ["pwd", "otp"],
  "acr": "urn:gatelite:acr:2",
  "roles": ["editor", "reader"],
  "resource_access": {
    "portal-api": {
      "roles": ["editor", "reader"]
    }
  }
}
```

### Validação local em Python

```python
import jwt

issuer = "https://auth.example.com"
jwks = jwt.PyJWKClient(f"{issuer}/oidc/jwks/")
signing_key = jwks.get_signing_key_from_jwt(token)

claims = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    issuer=issuer,
    audience="portal-api",
)

if claims.get("token_use") != "access":
    raise PermissionError("Tipo de token inválido")

roles = set(claims.get("resource_access", {}).get("portal-api", {}).get("roles", []))
if "reader" not in roles:
    raise PermissionError("Role reader obrigatória")
```

A API deve validar pelo menos assinatura, algoritmo, `iss`, `exp`, `aud` e `token_use`. Use `azp` quando também precisar limitar qual client pode chamar a API.

Para exigir segundo fator:

```python
if claims.get("acr") != "urn:gatelite:acr:2":
    raise PermissionError("MFA obrigatório")
```

Não use apenas a existência de uma role com nome conhecido sem validar `aud` e o namespace em `resource_access`.

## Autenticação em duas etapas

O 2FA usa TOTP RFC 6238 e funciona com Google Authenticator, Microsoft Authenticator, 1Password, Authy e aplicativos compatíveis.

Recursos:

- configuração por QR Code ou chave manual;
- secret cifrado no banco com AES-GCM;
- janela TOTP de um intervalo antes/depois;
- proteção contra reutilização do mesmo contador;
- desafio persistente vinculado à sessão e à senha atual;
- validade de cinco minutos;
- bloqueio temporário após cinco erros;
- dez recovery codes de uso único armazenados somente como hash;
- regeneração, desativação e reset administrativo;
- invalidação de sessões OIDC e refresh tokens após mudanças críticas.

### Políticas

Em **Configurações → Autenticação em duas etapas**:

- `optional`: cada usuário decide ativar;
- `admins`: obrigatório para superusuários, staff e operadores do console;
- `all`: obrigatório para todos os usuários.

Um client ou resource server também pode marcar **Exigir MFA**. O `/oidc/authorize/` realiza step-up antes de emitir o authorization code e os tokens recebem `amr`/`acr` da autenticação realmente realizada.

Recovery code produz `amr: ["pwd", "recovery"]` e `acr: urn:gatelite:acr:2`.

## Endpoints

| Endpoint | Método principal | Finalidade |
|---|---|---|
| `/.well-known/openid-configuration` | GET | Discovery canônico |
| `/oidc/.well-known/openid-configuration` | GET | Discovery alternativo |
| `/oidc/authorize/` | GET | Authorization Code |
| `/oidc/token/` | POST | Code, Refresh Token e Client Credentials |
| `/oidc/userinfo/` | GET | Claims do usuário pelo Bearer token |
| `/oidc/jwks/` | GET | Chaves públicas RSA |
| `/oidc/revoke/` | POST | Revogação de access/refresh token |
| `/oidc/introspect/` | POST | Estado de token para client confidencial |
| `/oidc/logout/` | GET | Encerramento da sessão OIDC |

O Discovery é a fonte de verdade para metadados, métodos de autenticação e claims suportadas.

### Endpoints de conta

| Endpoint | Método | Finalidade |
|---|---|---|
| `/account/profile/` | GET/POST | Editar nome, sobrenome e solicitar novo e-mail |
| `/account/email/resend/` | POST | Reenviar confirmação com throttle |
| `/account/email/confirm/?token=...` | GET/POST | Revisar e confirmar o endereço |
| `/password/reset/` | GET/POST | Solicitar recuperação sem enumerar contas |
| `/password/reset/<uid>/<token>/` | GET/POST | Definir nova senha |

A recuperação só envia mensagem para usuários ativos, com senha utilizável e e-mail atual confirmado. A resposta pública é idêntica para endereço inexistente, não confirmado ou válido.

### Refresh tokens

Um refresh token só é emitido quando:

- o client permite refresh tokens; e
- o scope solicitado inclui `offline_access`.

Cada uso rotaciona o token. A reutilização de um token antigo marca replay, revoga toda a família e encerra a sessão OIDC correspondente. Um refresh não pode ampliar os scopes originais.

### Revogação e JWT stateless

UserInfo e Introspection observam revogações e mudanças da versão de segurança imediatamente. Uma API que valida somente o JWT localmente pelo JWKS continuará aceitando um access token já emitido até `exp`. Mantenha access tokens curtos ou use Introspection quando revogação imediata for um requisito.

## Chaves e rotação

- A chave privada RSA é gerada pela aplicação.
- A chave privada fica cifrada com AES-GCM no banco.
- O console e o JWKS exibem somente dados públicos e o `kid`.
- Apenas uma chave fica ativa.
- Ao rotacionar, a anterior permanece no JWKS pelo maior TTL de JWT mais uma margem.
- Client secrets ficam somente como hashes adaptativos.

Faça backup do banco e preserve `KEY_ENCRYPTION_SECRET` separadamente. Perder qualquer um deles pode impedir a continuidade da assinatura ou a leitura dos fatores TOTP existentes.

## Operação e produção

### Limpeza periódica

Agende o comando abaixo para remover artefatos expirados antigos:

```bash
venv/bin/python manage.py cleanup_identity
```

Ele remove authorization codes, refresh tokens, JTIs revogados, sessões OIDC e desafios MFA além do período de retenção.

### Checklist de produção

- Defina `DJANGO_DEBUG=0`.
- Use valores fortes e persistentes para as duas chaves de ambiente.
- Publique um `OIDC_ISSUER` HTTPS estável.
- Use PostgreSQL para concorrência real.
- Execute `collectstatic` e sirva arquivos estáticos pelo proxy ou CDN.
- Use um servidor WSGI/ASGI adequado à produção.
- Configure proxy reverso, TLS, limites de requisição e rate limiting.
- Faça backups testados do banco e das configurações de ambiente.
- Monitore falhas de login, lockouts e eventos de auditoria.
- Configure e monitore o provedor SMTP, SPF, DKIM e DMARC do domínio remetente.
- Execute migrations antes de liberar uma nova versão.

O projeto aplica cookies seguros, HSTS e redirecionamento HTTPS automaticamente quando executado com as configurações de produção previstas.

### Escopo atual

GateLite não pretende reproduzir todos os módulos do Keycloak. O projeto não inclui realms, federação LDAP/AD, SCIM, WebAuthn/passkeys, login social, tela de consentimento ou registro dinâmico de clients. O segundo fator implementado é TOTP com recovery codes.

## Testes automatizados

A suíte está dividida em:

- [identity/tests.py](identity/tests.py): 45 testes de protocolo, segurança, roles, tokens, RBAC, 2FA, logout OIDC, retenção de chaves e lockout de login;
- [identity/tests_ui.py](identity/tests_ui.py): 19 testes de interface, formulários, labels, rotas e regressões de alinhamento.
- [identity/tests_account.py](identity/tests_account.py): 21 testes de perfil, confirmação de e-mail, recuperação, políticas persistidas, marca e controles.

Total atual: **85 testes automatizados**.

Os testes sempre rodam em SQLite, mesmo quando `DB_ENGINE=postgres` está definido no ambiente.

Execute localmente:

```bash
venv/bin/python manage.py test --verbosity=2
venv/bin/python manage.py check
venv/bin/python manage.py makemigrations --check --dry-run --noinput
```

Executar apenas as regressões de interface:

```bash
venv/bin/python manage.py test identity.tests_ui --verbosity=2
```

O workflow [.github/workflows/tests.yml](.github/workflows/tests.yml) executa automaticamente em `push`, `pull_request` e por acionamento manual:

- Python 3.12 e 3.13;
- `manage.py check`;
- detecção de migrations esquecidas;
- todos os 85 testes Django.

A cobertura comportamental inclui PKCE, clients públicos/confidenciais, Basic/Post, audiences, roles diretas e por grupos, roles compostas, service accounts, CORS, refresh replay, revogação, Introspection, JWT/JWKS, RBAC, políticas, login, MFA, recovery codes, lockout, templates, labels, filtros, paginação e métodos HTTP.

## Solução de problemas

### `DJANGO_SECRET_KEY é obrigatório em produção`

Defina `DJANGO_SECRET_KEY` e reinicie o processo. Isso ocorre quando `DJANGO_DEBUG=0`.

### `KEY_ENCRYPTION_SECRET é obrigatório em produção`

Defina uma chave separada e persistente. Não use um valor temporário a cada deploy.

### `redirect_uri inválido`

O valor enviado ao authorize e ao token endpoint deve ser idêntico a uma Redirect URI cadastrada, incluindo scheme, host, porta, path e barra final.

### `invalid_target`

A audience pedida não está na lista de audiences autorizadas do client chamador ou está inativa.

### `invalid_scope`

O client não possui um dos scopes solicitados. Em Authorization Code OIDC, `openid` é obrigatório.

### PKCE inválido

Clients públicos exigem `code_challenge_method=S256`. O mesmo `code_verifier`, entre 43 e 128 caracteres permitidos, deve ser enviado na troca do código.

### Token válido sem as roles esperadas

Confirme:

1. a claim `aud`;
2. o client ao qual a role pertence;
3. a atribuição direta ou por grupo;
4. a expiração da atribuição;
5. o conteúdo de `resource_access.<audience>.roles`.

### Access token revogado ainda aceito por uma API

Isso acontece quando a API faz apenas validação JWT local. Use TTL curto ou Introspection para checagem online.

### Erro ao descriptografar chaves ou TOTP após deploy

Verifique se `KEY_ENCRYPTION_SECRET` é exatamente o mesmo usado quando os dados foram criados.

### A confirmação ou recuperação não chega

Em desenvolvimento, o backend padrão imprime a mensagem no terminal. Em produção, confira `EMAIL_BACKEND`, host, porta, credenciais, TLS/SSL e `DEFAULT_FROM_EMAIL`. Verifique também os logs do provedor e as políticas SPF/DKIM/DMARC.

### Recuperação não envia para um e-mail cadastrado

O endereço precisa estar confirmado e ainda corresponder ao e-mail atual do usuário. Entre normalmente, abra **Minha conta → Editar dados** e solicite uma confirmação.

## Licença

Distribuído sob a [Licença MIT](LICENSE).
