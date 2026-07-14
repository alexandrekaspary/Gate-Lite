# GateLite

GateLite é um provedor de identidade e Single Sign-On construído com Django. Ele segue OpenID Connect, emite JWTs assinados com RSA, publica JWKS e oferece um console próprio para administrar usuários, grupos, clients e roles.

O modelo lembra o Keycloak, mas usa um único domínio de identidade: não existem realms ou uma camada de multi-tenancy.

## Recursos principais

- OpenID Connect Discovery e JWKS.
- Authorization Code com PKCE S256, Refresh Token com rotação e Client Credentials.
- Roles por client, herdadas por grupos, padrão e compostas, com audiences explícitas.
- TOTP/2FA com recovery codes e step-up por client.
- Confirmação de e-mail, recuperação de senha e bloqueio por força bruta.
- Chaves RSA cifradas no banco, rotação de chaves e de client secrets.
- Console administrativo com documentação embutida e log de auditoria (filtros, paginação e retenção configurável, com limpeza automática).
- Cadastro público opcional de usuários, com grupos padrão configuráveis.

## Instalação

Requisitos: Python 3.12 ou 3.13; SQLite (padrão) ou PostgreSQL (recomendado em produção).

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python manage.py migrate
venv/bin/python manage.py runserver
```

Acesse:

- Console: `http://localhost:8000/`
- Conta do usuário: `http://localhost:8000/account/`
- Discovery: `http://localhost:8000/.well-known/openid-configuration`

## Configuração

O Django carrega o arquivo `.env` na raiz do projeto e também lê variáveis do ambiente do processo; estas últimas têm precedência. A suíte de testes não carrega esse arquivo. Use [.env.example](.env.example) como referência. Em produção são obrigatórios `DJANGO_SECRET_KEY`, `KEY_ENCRYPTION_SECRET`, `DJANGO_ALLOWED_HOSTS` e `OIDC_ISSUER`, com `DJANGO_DEBUG=0`.

Na primeira migration, o GateLite cria o superusuário `admin` com a senha temporária `123456`. A troca da senha é obrigatória no primeiro login; não use essa credencial em produção antes de alterá-la.

Gere valores independentes e longos para as duas chaves:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(64))'
```

Não altere `KEY_ENCRYPTION_SECRET` em um ambiente existente: a troca direta torna ilegíveis as chaves privadas RSA e os secrets TOTP já persistidos.

### E-mail (SMTP)

O SMTP é configurado no Console, em **Configurações → E-mail, SMTP e recuperação de senha** — não no `.env`. Servidor, porta, usuário, remetente e o modo TLS ficam no banco; a senha SMTP é cifrada com `KEY_ENCRYPTION_SECRET` e nunca volta a ser exibida, apenas substituída ou removida. O interruptor **Habilitar envio de e-mails** suspende confirmações e recuperações sem apagar a configuração.

Variáveis de ambiente opcionais relacionadas:

| Variável | Padrão | Efeito |
|---|---|---|
| `EMAIL_ENABLED` | `1` | Com `0`, desliga todo envio de e-mail, independentemente da configuração do console. |
| `EMAIL_TIMEOUT` | `10` | Timeout da conexão SMTP, em segundos. |
| `DEFAULT_FROM_EMAIL` | `GateLite <no-reply@localhost>` | Remetente usado quando o campo **Remetente padrão** está vazio. |
| `EMAIL_BACKEND` | backend SMTP do banco | Substitui o mecanismo de envio (útil em testes, ex.: backend de console do Django). |

## Docker

```bash
docker build -t gatelite .
docker run --rm -p 8000:8000 --env-file .env gatelite
```

O entrypoint aplica as migrations pendentes antes de aceitar tráfego.

## Documentação

A documentação completa fica embutida no console (menu **Documentação**) e nas páginas Markdown em [docs/console/](docs/console/):

- [Visão geral](docs/console/index.md)
- [Primeiros passos](docs/console/primeiros-passos.md)
- [Usuários](docs/console/usuarios.md)
- [Grupos](docs/console/grupos.md)
- [Clients](docs/console/clients.md)
- [Roles](docs/console/roles.md)
- [Configurações](docs/console/configuracoes.md)
- [Auditoria](docs/console/auditoria.md)
- [Integração OIDC](docs/console/integracao.md)

## Testes

```bash
venv/bin/python manage.py test --verbosity=2
```

## Licença

Distribuído sob a [Licença MIT](LICENSE).
