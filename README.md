# GateLite

GateLite é um provedor de identidade e Single Sign-On em Django. Implementa OpenID Connect, emite JWTs RS256, publica JWKS e oferece um console para usuários, grupos, clients, roles, segurança e auditoria.

## Recursos

- Discovery, Authorization Code com PKCE, Refresh Token rotativo e Client Credentials.
- Clients para SPA, mobile/desktop, backend web, serviço sem usuário e API.
- Wizard unificado de criação/edição com presets de protocolo, URLs, CORS, scopes e múltiplas roles.
- Roles herdadas por grupos ou atribuídas diretamente a usuários.
- Criação e rotação de client secrets com janela de sobreposição.
- TOTP/2FA, recovery codes e exigência por política ou client.
- Confirmação de e-mail, recuperação de senha e proteção contra força bruta.
- Chaves RSA cifradas, rotação e JWKS.
- Auditoria com filtros, retenção e suporte seguro a IP encaminhado por proxy.
- Cadastro público opcional com grupos padrão.

## Instalação local

Requer Python 3.12/3.13 e SQLite ou PostgreSQL.

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python manage.py migrate
venv/bin/python manage.py runserver
```

- Console: `http://localhost:8000/`
- Minha conta: `http://localhost:8000/account/`
- Discovery: `http://localhost:8000/.well-known/openid-configuration`

Um banco novo recebe o superusuário `admin` com senha temporária `123456`, caso esse username ainda não exista. Troque-a no primeiro acesso.

## Configuração

Copie [.env.example](.env.example). Em produção, use `DJANGO_DEBUG=0` e defina pelo menos `DJANGO_SECRET_KEY`, `KEY_ENCRYPTION_SECRET`, `DJANGO_ALLOWED_HOSTS` e `OIDC_ISSUER`.

Gere segredos independentes:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(64))'
```

Não troque `KEY_ENCRYPTION_SECRET` diretamente em um ambiente existente: chaves privadas, TOTP e outros dados cifrados ficariam ilegíveis.

SMTP é configurado no console em **Configurações → E-mail e recuperação**. A senha fica cifrada no banco.

### Proxy e IP de auditoria

Atrás de um proxy que sempre define o protocolo:

```env
TRUST_PROXY_SSL_HEADER=1
```

Para registrar o IP original encaminhado por um load balancer confiável:

```env
TRUST_X_FORWARDED_FOR=1
TRUSTED_PROXY_COUNT=1
```

Não habilite `TRUST_X_FORWARDED_FOR` quando a aplicação puder ser acessada diretamente sem passar pelo proxy.

## Docker

```bash
docker build -t gatelite .
docker run --rm -p 8000:8000 --env-file .env gatelite
```

O build coleta os estáticos; o entrypoint aplica migrations antes de iniciar o Gunicorn.

## Documentação

A documentação está embutida no console e versionada em [docs/console](docs/console/): visão geral, primeiros passos, usuários, grupos, clients, roles, configurações, auditoria e integração OIDC.

## Testes

```bash
venv/bin/python manage.py test
```

## Licença

MIT. Consulte [LICENSE](LICENSE).
