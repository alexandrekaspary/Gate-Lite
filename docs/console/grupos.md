# Grupos

Grupos distribuem acesso em escala. Exigem a permissão `Pode gerenciar grupos`.

## Formulário

| Etapa | Campos |
|---|---|
| **Identificação** | Nome do grupo. |
| **Membros** | Usuários que pertencem ao grupo. |
| **Roles de clients** | Autorizações herdadas por todos os membros. |
| **Administração** | Permissões do console herdadas pelos membros. |

As listas possuem busca e contador de seleção. Uma role aparece como `Client · Role`, deixando explícita a aplicação à qual pertence.

## Herança

- O efeito de vários grupos é aditivo.
- Roles repetidas são deduplicadas no token.
- Remover um membro ou uma role afeta os próximos tokens emitidos.
- Tokens já emitidos continuam válidos até expirar; encerre sessões quando precisar de corte imediato.

## Cadastro público

Configurações pode definir grupos concedidos automaticamente a quem usa `/register/`. Revise com cuidado qualquer permissão administrativa nesses grupos, pois ela também será concedida aos novos cadastros.

## Boas práticas

- Modele grupos por função ou equipe, como `Financeiro` e `Suporte N2`.
- Prefira grupo → role para acessos compartilhados.
- Use roles diretas no usuário somente para exceções.
- Ao conceder permissões administrativas por grupo, considere a política de MFA para administradores.
