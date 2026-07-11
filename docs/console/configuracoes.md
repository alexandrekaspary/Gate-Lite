# Configurações

A política de segurança é global, persistida no banco e editada em **Configurações** (permissão `Pode gerenciar políticas de segurança`; leitura também liberada para quem gerencia chaves ou permissões). As alterações valem para todo o ambiente a partir das próximas emissões e logins — tokens já emitidos não são revogados.

## Política de senha

Aplicada na criação de usuário, no autosserviço e na recuperação.

| Campo | Efeito |
|---|---|
| **Tamanho mínimo** | Entre 8 e 128 caracteres. |
| **Exigir letra maiúscula / minúscula / número / caractere especial** | Cada regra ativa vira uma exigência independente, com mensagem própria no formulário. |

Além destas, o Django sempre bloqueia senhas parecidas com os dados do usuário, senhas comuns e senhas totalmente numéricas.

## Autenticação em duas etapas

| Modo | Efeito |
|---|---|
| **Opcional** | Cada usuário decide ativar o TOTP em Minha conta. |
| **Obrigatório para administradores** | Superusuários, staff e qualquer usuário com permissão administrativa precisam configurar o TOTP no próximo acesso. |
| **Obrigatório para todos** | Todos os usuários. |

Independentemente do modo global, um client ou resource server com **Exigir MFA** força o step-up naquela aplicação. Quem já tem TOTP configurado sempre passa pelo desafio ao entrar.

## Tokens, sessões e client secrets

| Campo | O que controla | Considerações |
|---|---|---|
| **Validade do access token** | `exp` dos access tokens | APIs que validam só o JWT aceitam o token até expirar, mesmo revogado. TTL curto (5 min) limita essa janela. |
| **Validade do ID token** | `exp` dos ID tokens | Consumido no login; pode ser curto. |
| **Validade máxima do refresh token** | Vida total da família de refresh | A rotação a cada uso **não** estende este prazo — é absoluto desde o login. |
| **Validade da sessão SSO** | Sessão OIDC criada na autorização | Expirada a sessão, novos códigos/refreshes deixam de funcionar e o usuário loga de novo. |
| **Sobreposição de secrets na rotação** | Janela em que o secret anterior ainda vale após gerar um novo | Dá tempo de atualizar o deploy da aplicação sem downtime. |

## E-mail, SMTP e recuperação de senha

A seção reúne a conexão SMTP do ambiente e a validade dos links enviados por e-mail.

### Servidor SMTP

| Campo | O que controla |
|---|---|
| **Habilitar envio de e-mails** | Liga ou desliga as mensagens de confirmação e recuperação, sem apagar a configuração. Com o envio habilitado, o servidor SMTP passa a ser obrigatório. |
| **Servidor e porta SMTP** | Endereço e porta do provedor. Na maioria dos provedores: 587 com STARTTLS ou 465 com SSL/TLS direto. |
| **Usuário e senha SMTP** | Credenciais de autenticação; deixe o usuário vazio se o servidor não exigir login. A senha é cifrada no banco com `KEY_ENCRYPTION_SECRET`; depois de salva, só pode ser substituída ou removida, nunca consultada em texto. |
| **STARTTLS / SSL/TLS direto** | Modo de criptografia da conexão. Ative somente um, conforme a orientação do provedor. |
| **Remetente padrão** | Endereço que aparece como remetente; aceita o formato `GateLite <no-reply@exemplo.com>`. |
| **Remover senha SMTP armazenada** | Apaga a senha cifrada. O interruptor só aparece quando há senha salva. |

A variável de ambiente `EMAIL_ENABLED=0` desliga os envios globalmente, independentemente desta tela — útil em ambientes de homologação.

### Validade dos links enviados

| Campo | O que controla |
|---|---|
| **Validade da confirmação de e-mail** | Prazo do link de confirmação de endereço. |
| **Intervalo mínimo de reenvio** | Anti-spam do botão "reenviar confirmação". |
| **Validade da recuperação de senha** | Prazo do link de redefinição. A validade é conferida **ao abrir o link**, então ajustar a política afeta links já enviados. |
| **Intervalo mínimo entre recuperações** | Anti-bombardeio: pedidos repetidos dentro da janela não reenviam e-mail, com resposta pública idêntica (sem revelar se a conta existe). |

## Proteção contra força bruta

| Campo | O que controla |
|---|---|
| **Tentativas de senha antes do bloqueio** | Erros consecutivos de senha no login que disparam o bloqueio da conta. |
| **Duração do bloqueio de login** | Tempo em que até a senha correta é recusada (HTTP 429). |

O contador zera a cada login bem-sucedido. O desafio TOTP tem bloqueio próprio e independente (5 erros → 5 minutos). Bloqueios geram o evento de auditoria `authentication.locked_out`. Recomenda-se rate limiting por IP também no proxy reverso, como camada adicional.

## Acessos e criptografia

Atalhos no fim da página de Configurações:

- **Permissões administrativas** — controle de acesso ao console ([detalhes](usuarios)).
- **Roles dos clients** — todas as roles, com filtro por client ([detalhes](roles)).
- **Chaves e JWKS** — material de assinatura RSA.

### Chaves de assinatura

- A chave privada é gerada pela aplicação e fica **cifrada com AES-GCM** no banco; nenhum arquivo de chave existe em disco.
- Apenas uma chave fica ativa; o console e o JWKS expõem só os dados públicos e o `kid`.
- Ao **rotacionar**, a chave anterior permanece publicada (e aceita) pelo maior TTL de JWT mais uma margem, para que tokens em circulação continuem validáveis; depois disso é rejeitada em qualquer verificação.
- **Não troque o `KEY_ENCRYPTION_SECRET`** de um ambiente existente sem processo de recriptografia: as chaves privadas e os secrets TOTP persistidos ficariam ilegíveis. Faça backup do banco e desse segredo separadamente.
