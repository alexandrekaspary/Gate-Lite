# Grupos

Grupos são o mecanismo de acesso em escala: em vez de atribuir roles usuário por usuário, vincule roles ao grupo e adicione as pessoas. Exige a permissão `Pode gerenciar grupos`.

## Tutorial: criar um grupo

1. Abra **Grupos → Criar grupo**.
2. Preencha os campos:

| Campo | O que significa |
|---|---|
| **Nome** | Identificador do grupo. É emitido no claim `groups` do JWT quando o scope `groups` é solicitado — escolha nomes que façam sentido para as aplicações (ex.: `Financeiro`). |
| **Usuários do grupo** | Os membros. Todos herdam imediatamente o que o grupo concede. |
| **Roles de clients** | Roles herdadas por todos os membros, exibidas como `Client · Role`. É aqui que grupos viram acesso às aplicações. |
| **Permissões administrativas do grupo** | Permissões do console herdadas pelos membros. Ideal para delegar operação: um grupo "Operadores de suporte" com `Pode gerenciar usuários`, por exemplo. |

3. Salve. Não é preciso reemitir nada: novos tokens já saem com as roles herdadas; tokens já emitidos valem até expirar.

## Como a herança funciona

- Um usuário pode estar em vários grupos; o efeito é **aditivo** (união deduplicada de roles e permissões).
- A herança de roles respeita a expiração da atribuição: uma role vinculada ao grupo com data de expiração deixa de ser emitida ao vencer.
- Remover um usuário do grupo remove as roles herdadas nos **próximos** tokens. Para cortar acesso imediato, revogue as sessões OIDC do usuário (na edição do usuário ou pelo próprio autosserviço).

## Grupos e a política de acesso restrito

Um client com política `Restrito` só autentica usuários com role atribuída, autorização direta ou que pertençam a um **grupo autorizado** no client. Ou seja, o grupo também pode ser a porta de entrada do client, mesmo sem role — veja [Clients](clients).

## Boas práticas

- Modele grupos por função ou equipe, não por aplicação ("Suporte N2", e não "Usuários do portal-web").
- Prefira `Usuário → Grupo → Role`; deixe atribuições diretas para exceções auditáveis.
- Ao delegar permissões administrativas via grupo, lembre que a política de MFA `Obrigatório para administradores` passa a valer para os membros.
- O claim `groups` só inclui grupos **relevantes para o client** (autorizados nele ou com roles do client), evitando vazar a estrutura organizacional inteira para qualquer aplicação.
