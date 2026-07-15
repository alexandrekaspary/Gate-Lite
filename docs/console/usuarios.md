# Usuários

Usuários representam identidades humanas. A área exige `Pode gerenciar usuários` e oferece busca, filtro de status, criação, edição e exclusão.

## Criação

### Identidade

- **Usuário**: identificador de login e claim `preferred_username`.
- **Nome e sobrenome**: claims do scope `profile`.
- **E-mail**: usado em confirmação e recuperação; não diferencia maiúsculas e minúsculas.
- **Idioma e fuso horário**: começam com os padrões de Configurações.

### Segurança

- Senha e confirmação seguem a política global.
- **Exigir troca de senha no próximo login** restringe a conta até a troca.
- Usuário inativo não autentica.

### Acessos

- **Grupos** concedem roles de aplicações e permissões administrativas.
- **Roles diretas de clients** atendem exceções individuais.

### Administração

- **Acesso básico** representa o autosserviço concedido a toda conta.
- **Staff** permite acesso ao Django Admin.
- **Permissões administrativas** liberam áreas específicas do console.

## Edição

A edição também permite:

- definir uma nova senha, revogando outras sessões;
- marcar ou remover a troca obrigatória;
- redefinir o TOTP e recovery codes;
- alterar e-mail, iniciando nova confirmação;
- conceder superusuário, quando o operador possui autoridade para isso.

## Permissões administrativas

| Permissão | Libera |
|---|---|
| Acessar o console | Visão geral e navegação administrativa. |
| Gerenciar usuários | CRUD de usuários. |
| Gerenciar grupos | Membros, roles e permissões de grupos. |
| Gerenciar clients e roles | Wizard de clients, roles e client secrets. |
| Gerenciar políticas de segurança | Página Configurações. |
| Gerenciar chaves de assinatura | Rotação RSA e JWKS. |
| Gerenciar permissões administrativas | Cadastro dessas permissões. |
| Visualizar auditoria | Eventos, filtros e retenção. |

Permissões administrativas não são roles de aplicação e não entram no JWT como autorização de negócio.

## Cadastro público e autosserviço

Quando habilitado, `/register/` cria contas com os grupos padrão configurados. Em **Minha conta**, cada usuário pode editar perfil, trocar senha, confirmar e-mail, configurar 2FA e encerrar sessões OIDC.

Eventos críticos — troca de senha, redefinição/alteração de 2FA e desativação — invalidam sessões e refresh tokens conforme a política de segurança.
