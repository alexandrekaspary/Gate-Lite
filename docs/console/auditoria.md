# Auditoria

A tela **Auditoria** lista os eventos registrados pelo GateLite: quem fez o quê, quando e a partir de qual IP. Exige a permissão `Pode visualizar o log de auditoria`.

## Filtros e paginação

| Filtro | O que faz |
|---|---|
| **Busca** | Procura por ação, usuário responsável, tipo/identificador do alvo e IP (`icontains`). |
| **Ação** | Lista suspensa com as ações já registradas no banco, para localizar um tipo específico de evento. |
| **De / Até** | Intervalo de datas aplicado ao momento do evento. |

Os resultados são paginados em blocos de 50, do mais recente para o mais antigo.

## O que é registrado

Cada evento guarda ator (quando há um usuário autenticado por trás da ação), ação, tipo e identificador do alvo, metadados em JSON e o IP de origem. Entre os eventos cobertos:

| Categoria | Exemplos de ação |
|---|---|
| **Autenticação** | `authentication.login`, `authentication.failed`, `authentication.locked_out` |
| **Contas** | `users.created`, `users.updated`, `users.deleted`, `user.self_registered`, `profile.updated` |
| **E-mail** | `email.confirmation_requested`, `email.confirmed`, `email.changed_directly` |
| **Senha** | `password.reset_requested`, `password.reset_completed` |
| **2FA** | `mfa.enabled`, `mfa.disabled`, `mfa.challenge_succeeded`, `mfa.challenge_failed`, `mfa.recovery_codes_regenerated` |
| **Administração** | `groups.*`, `clients.*`, `roles.*`, `permissions.*`, `security_policy.updated`, `email_configuration.updated`, `signing_key.rotated` |

Um evento com ator vazio ("Sistema" na listagem) significa uma ação sem usuário autenticado no momento — por exemplo, uma tentativa de login com um usuário inexistente.

## Retenção e limpeza automática

O campo **Retenção do log de auditoria**, em [Configurações](configuracoes), define por quantos dias um evento permanece armazenado antes de ser apagado. A limpeza roda automaticamente em segundo plano, a cada 24 horas — sem depender de um agendador externo — e também remove códigos, tokens e sessões OIDC expirados. Reduzir o prazo não apaga nada na hora, apenas no próximo ciclo.

Para forçar uma limpeza imediata (por exemplo, logo após reduzir a retenção), rode `python manage.py cleanup_identity` — opcional, nunca necessário para o funcionamento normal.
