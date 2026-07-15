# Primeiros passos

## 1. Proteja o primeiro acesso

Em um banco novo, as migrations criam o superusuário `admin` com a senha temporária `123456`, somente se esse username ainda não existir. Entre e troque a senha imediatamente; enquanto a troca estiver pendente, o usuário fica restrito à tela de nova senha.

## 2. Revise Configurações

Use a ordem apresentada na página:

1. **Cadastro de usuários** — decida se `/register/` ficará público e quais grupos serão concedidos.
2. **Localização** — escolha idioma e fuso padrão dos novos usuários.
3. **E-mail e recuperação** — configure SMTP, remetente e validade dos links.
4. **Política de senha** — defina tamanho e complexidade.
5. **Proteção de login** — configure tentativas e bloqueio.
6. **Autenticação em duas etapas** — escolha a política global de TOTP.
7. **Tokens, sessões e secrets** — revise TTLs e a sobreposição de client secrets.
8. **Auditoria** — defina a retenção.

## 3. Crie os clients

Abra **Clients → Novo client**. O mesmo wizard é usado na edição:

1. escolha o tipo da aplicação e, se houver login de usuário, decida se ela exige 2FA;
2. confira o protocolo preenchido automaticamente e ajuste os scopes;
3. informe Redirect URIs quando o tipo usa login e configure CORS quando houver chamadas do navegador;
4. cadastre uma ou mais roles no formato `nome | descrição`.

Clients confidenciais geram um client secret depois de salvar. Copie o valor antes de fechar o aviso.

## 4. Distribua as roles

Crie grupos por função ou equipe, vincule as roles dos clients e adicione os usuários. Use roles diretas no usuário apenas para exceções.

## 5. Delegue a administração

Conceda permissões específicas do console, preferencialmente por grupos. Evite transformar operadores comuns em superusuários.

## 6. Prepare produção

- Use `DJANGO_DEBUG=0`, segredos fortes e `OIDC_ISSUER` HTTPS estável.
- Guarde backup do banco e de `KEY_ENCRYPTION_SECRET` separadamente.
- Restrinja o acesso direto quando houver proxy/load balancer.
- Para registrar o IP real na auditoria, configure `TRUST_X_FORWARDED_FOR=1` e a quantidade correta em `TRUSTED_PROXY_COUNT`.
- Teste login, 2FA, envio de e-mail, rotação de client secret e validação de JWT antes de liberar o ambiente.
