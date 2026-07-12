# Usuários

Gerencie identidades em **Usuários** no menu lateral. A listagem tem busca por username, nome ou e-mail e filtro por status (ativo/inativo). Exige a permissão `Pode gerenciar usuários`.

## Tutorial: criar um usuário

O formulário é dividido em quatro etapas.

### Etapa 1 — Identidade

| Campo | O que significa |
|---|---|
| **Usuário (username)** | Identificador de login. No autosserviço o usuário **nunca** consegue alterá-lo; ele aparece nos JWTs como `preferred_username`. |
| **Nome / Sobrenome** | Compõem os claims `given_name`, `family_name` e `name` quando o scope `profile` é solicitado. |
| **E-mail** | Opcional, mas necessário para confirmação e recuperação de senha. Endereços são únicos (sem diferenciar maiúsculas). Ao salvar, o GateLite envia automaticamente um link de confirmação. |
| **Idioma / Fuso horário** | Pré-selecionados com os padrões definidos em [Configurações](configuracoes). Saem nos JWTs como os claims `locale` e `zoneinfo` quando o scope `profile` é solicitado. |

### Etapa 2 — Segurança

| Campo | O que significa |
|---|---|
| **Senha / Confirmação** | Validadas pela [política de senha](configuracoes) vigente. |
| **Exigir troca de senha no próximo login** | Útil ao definir uma senha temporária: depois de autenticar, o usuário fica restrito à tela de troca de senha até concluir a alteração. |
| **Ativo** | Desmarque em vez de excluir a conta: um usuário inativo não faz login e tem sessões OIDC e refresh tokens revogados imediatamente. |

### Etapa 3 — Acessos

| Campo | O que significa |
|---|---|
| **Grupos** | O usuário herda as roles de clients e as permissões administrativas de todos os grupos. Caminho recomendado para qualquer acesso compartilhado. |
| **Roles diretas de clients** | Exceções individuais. Aparecem como `Client · Role`. Prefira grupos — atribuições diretas dificultam revisão de acesso. |

Use o campo **Filtrar opções…** de cada lista para localizar itens rapidamente.

### Etapa 4 — Administração

| Campo | O que significa |
|---|---|
| **Acesso básico** | Informativo: todo usuário recebe automaticamente `ver o próprio perfil` e `alterar a própria senha`. |
| **Membro da equipe (staff)** | Permite entrar no Django Admin (`/admin/`). O Admin usa o mesmo fluxo de login e 2FA do GateLite. Raramente necessário. |
| **Superusuário** (só na edição) | Ignora todas as verificações de permissão, inclusive a política de acesso restrito dos clients. Mantenha pouquíssimos. |
| **Permissões administrativas** | Acessos ao console, detalhados abaixo. |

## Permissões administrativas

Estas permissões controlam o próprio GateLite e **não** são enviadas às aplicações:

| Permissão | Libera |
|---|---|
| Pode acessar o console de identidade | O menu Console e a Visão geral |
| Pode gerenciar usuários | Listar, criar, editar e excluir usuários |
| Pode gerenciar grupos | Grupos e seus vínculos |
| Pode gerenciar clients e roles | Clients OIDC e as roles de cada client |
| Pode gerenciar políticas de segurança | Editar as Configurações |
| Pode gerenciar chaves de assinatura | Ver e rotacionar chaves RSA |
| Pode gerenciar permissões administrativas | Conceder/editar estas próprias permissões |

Qualquer permissão administrativa (ou superusuário/staff) também classifica o usuário como "administrador" para a política de MFA `Obrigatório para administradores`.

## Edição de usuário

Além dos campos de criação, a edição oferece:

- **Nova senha / Confirme a nova senha** — deixe ambas em branco para manter a atual. As duas precisam coincidir e seguem a política de senha. Definir uma senha revoga as outras sessões do usuário.
- **Exigir troca de senha no próximo login** — restringe o usuário à tela de troca de senha depois que ele se autenticar. A tela pede somente a nova senha e sua confirmação, sem pedir a senha temporária/anterior. Pode ser usado junto de uma senha temporária ou para exigir a renovação da senha atual.
- **Redefinir 2FA** — remove o autenticador e os recovery codes. Use quando o usuário perdeu o dispositivo; ele configura o TOTP de novo no próximo login (conforme a política).
- **E-mail** — trocar o endereço aqui deixa a confirmação **pendente**: o endereço só passa a valer como confirmado depois que o dono clicar no link. A claim `email_verified` reflete exatamente isso.

## Comportamentos automáticos

- **Confirmação de e-mail**: criada a conta com e-mail, um link temporário e de uso único é enviado. O reenvio respeita o intervalo configurado.
- **Bloqueio por força bruta**: erros consecutivos de senha bloqueiam temporariamente o login (configurável). O contador zera em login bem-sucedido; o desafio TOTP tem um bloqueio próprio e independente.
- **Revogação em eventos críticos**: trocar senha, confirmar novo e-mail, ativar/desativar 2FA ou desativar a conta revoga sessões web, sessões OIDC e refresh tokens.
- **Autosserviço**: em **Minha conta**, o usuário edita nome e e-mail (nunca o username), troca a senha, gerencia o 2FA e encerra sessões OIDC que não reconhece.
