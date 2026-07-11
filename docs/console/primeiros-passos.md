# Primeiros passos

Este roteiro cobre a configuração de um ambiente novo, na ordem que evita retrabalho.

## 1. Ajuste a política de segurança

Abra **Configurações** e revise, nesta ordem:

1. **Política de senha** — requisitos aplicados a toda senha nova (cadastro, autosserviço e reset).
2. **Autenticação em duas etapas** — comece com `Opcional` ou `Obrigatório para administradores`; mude para `Obrigatório para todos` quando os usuários estiverem orientados.
3. **Tokens, sessões e secrets** — os padrões são seguros; encurte o access token se suas APIs validam apenas o JWT localmente.
4. **E-mail e recuperação** — validade dos links enviados por e-mail.
5. **Proteção contra força bruta** — tentativas e duração do bloqueio de login.

Cada campo está explicado em [Configurações](configuracoes).

## 2. Confirme o envio de e-mail

Confirmação de endereço e recuperação de senha dependem de SMTP configurado no ambiente (`EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `DEFAULT_FROM_EMAIL`). Em desenvolvimento, o backend padrão imprime as mensagens no terminal do servidor.

## 3. Cadastre os clients

Crie um client para cada aplicação — SPA, API, backend, service account. Siga o tutorial em [Clients](clients). Para o caso comum "frontend + API":

1. crie o **resource server** (a API) primeiro;
2. crie o client do frontend e inclua a API nas **audiences permitidas**;
3. crie as [roles](roles) dentro da API.

## 4. Estruture grupos e usuários

1. Crie [grupos](grupos) espelhando as equipes ou funções ("Financeiro", "Suporte").
2. Vincule as roles dos clients aos grupos.
3. Crie os [usuários](usuarios) e associe-os aos grupos.

O caminho recomendado é sempre `Usuário → Grupo → Role do client`; use atribuições diretas apenas para exceções individuais.

## 5. Delegue a administração

Usuários novos recebem somente autosserviço (ver o próprio perfil e trocar a própria senha). Para dar acesso ao console a outros operadores, conceda permissões administrativas específicas — de preferência através de um grupo (ex.: um grupo "Operadores" com `Pode gerenciar usuários`). Evite multiplicar superusuários.

## Checklist final

- [ ] `DJANGO_DEBUG=0`, segredos fortes e `OIDC_ISSUER` HTTPS estável no ambiente
- [ ] SMTP testado (peça uma confirmação de e-mail e verifique a caixa de entrada)
- [ ] Política de senha e MFA definidas
- [ ] Clients criados com Redirect URIs exatas
- [ ] Roles vinculadas a grupos, usuários nos grupos
- [ ] Backup do banco e do `KEY_ENCRYPTION_SECRET` (guardados separadamente)
