# Roles dos clients

Uma role é uma autorização pertencente a um client. Ela é emitida no access token nos claims `roles` e `resource_access.<client_id>.roles`.

## Definir roles

Roles não possuem uma tela de cadastro separada. Crie ou edite o client e use a última etapa do wizard:

```text
reader | Consulta dados
editor | Altera dados
```

Cada linha exige um nome compatível com slug e uma descrição. O nome é único dentro do client. Na edição, omitir uma role existente remove essa role e suas atribuições.

## Atribuir roles

Há dois caminhos no console:

- **Grupos → Roles de clients**: todos os membros herdam as roles selecionadas. É o caminho recomendado.
- **Usuários → Roles diretas de clients**: use para exceções individuais.

Uma mesma pessoa pode receber a mesma role por mais de um caminho; o JWT contém uma lista deduplicada.

## Consumir na API

Exemplo de access token destinado ao client `portal-api`:

```json
{
  "aud": "portal-api",
  "roles": ["reader", "editor"],
  "resource_access": {
    "portal-api": { "roles": ["reader", "editor"] }
  }
}
```

A API deve validar assinatura, algoritmo, issuer, expiração e audience antes de confiar nas roles. O mesmo nome pode existir em clients diferentes, portanto nunca autorize apenas pelo texto da role sem validar `aud`.

Superusuários administram o GateLite, mas não recebem automaticamente roles das aplicações.
