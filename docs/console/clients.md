# Clients OIDC

Um client representa uma aplicação integrada. Criação e edição usam o mesmo wizard simplificado e exigem a permissão `Pode gerenciar clients e roles`.

## Tipos e presets

| Tipo escolhido | Client | Fluxos automáticos | Secret |
|---|---|---|---:|
| **SPA — aplicação no navegador** | Público | Authorization Code, Refresh Token e PKCE | Não |
| **Aplicativo mobile ou desktop** | Público | Authorization Code, Refresh Token e PKCE | Não |
| **Backend web com login de usuário** | Confidencial | Authorization Code, Refresh Token e PKCE | Sim |
| **Serviço sem usuário — máquina a máquina** | Confidencial | Client Credentials | Sim |
| **API que recebe e valida tokens** | Confidencial | Nenhum fluxo de login | Sim |

Os campos técnicos ficam visíveis na etapa Protocolo, marcados como automáticos. Trocar o tipo atualiza os valores. O servidor reaplica o preset ao salvar, evitando combinações inválidas.

## Etapa Aplicação

| Campo | Uso |
|---|---|
| **Nome** | Identificação no console. |
| **Client ID** | Identificador OIDC; pode ser gerado automaticamente na criação. |
| **Tipo de aplicação** | Define o preset da tabela acima. |
| **Exigir autenticação em dois fatores** | Força MFA neste client quando há login de usuário. |
| **Ativo** | Client inativo não autentica e perde suas sessões OIDC. |

## Etapa Protocolo

Tipo do client, método de autenticação, Authorization Code, Refresh Token, Client Credentials e PKCE são somente leitura. **Scopes permitidos** continuam editáveis:

- aplicações com login começam com `openid profile email groups offline_access`;
- serviços começam com `api.read`;
- APIs começam com `api.read api.write`.

Adapte scopes customizados ao domínio da aplicação. Authorization Code exige `openid`.

Na edição de um client confidencial, marque **Gerar novo client secret** para rotacionar a credencial. O novo valor aparece uma vez após salvar; o anterior permanece válido durante a janela de sobreposição configurada.

## Etapa URLs

- **Redirect URIs**: obrigatórias para tipos com Authorization Code. A correspondência é exata; HTTP só é permitido em loopback.
- **Post logout redirect URIs**: destinos permitidos após logout.
- **Web origins (CORS)**: origens `scheme://host:porta` autorizadas a chamar endpoints OIDC pelo navegador. Não inclua caminho, query ou fragmento.

Tipos sem login não exibem redirects, mas podem configurar CORS se realmente houver um consumidor no navegador.

## Etapa Roles

Informe uma role por linha:

```text
reader | Consulta dados
editor | Altera dados
admin | Administração da aplicação
```

Nome e descrição são obrigatórios. Nomes repetidos ou inválidos são rejeitados. Na edição, a lista representa todas as roles atuais: remover uma linha remove a role e seus vínculos.

As atribuições a grupos e usuários são feitas nos respectivos formulários, não no client.

## Client secret

Clients confidenciais geram um secret ao serem criados. O aviso após salvar permite copiar ou ocultar o valor e não volta a exibi-lo. Para renovar, use **Gerar novo client secret** na edição. O banco armazena somente o hash.

Clients públicos nunca mantêm secrets. Converter um client para público revoga os existentes; converter para confidencial gera uma credencial quando não houver uma ativa.
