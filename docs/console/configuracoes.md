# Configurações

A página reúne a política global e segue a ordem operacional abaixo. Alterações afetam novos logins e novas emissões; não reescrevem tokens já emitidos.

## 1. Cadastro de usuários

- **Habilitar cadastro** publica `/register/` e o link no login.
- **Grupos padrão** são concedidos automaticamente a novos cadastros públicos.

O cadastro fica desativado por padrão.

## 2. Localização

Idioma e fuso horário padrão são usados apenas em novos usuários. Cada pessoa pode manter preferências próprias depois.

## 3. E-mail e recuperação

Configure habilitação, servidor, porta, usuário, senha, STARTTLS ou SSL direto e remetente. A senha SMTP fica cifrada e nunca é exibida novamente.

Também são definidos:

- validade e intervalo de reenvio da confirmação de e-mail;
- validade e intervalo de novos pedidos de recuperação de senha.

## 4. Política de senha

Defina tamanho mínimo e exigências de maiúscula, minúscula, número e caractere especial. As validações adicionais do Django continuam bloqueando senhas comuns, numéricas ou semelhantes aos dados do usuário.

## 5. Proteção de login

Configure quantos erros consecutivos bloqueiam a conta e por quantos segundos. O contador zera em um login bem-sucedido. O desafio TOTP possui proteção própria.

## 6. Autenticação em duas etapas

| Modo | Efeito |
|---|---|
| **Opcional** | O usuário decide se ativa TOTP. |
| **Obrigatório para administradores** | Operadores do console devem configurar TOTP. |
| **Obrigatório para todos** | Toda identidade humana deve configurar TOTP. |

Um client pode exigir 2FA individualmente na primeira etapa de seu wizard.

## 7. Tokens, sessões e secrets

| Campo | Controla |
|---|---|
| Access token | Expiração dos tokens usados pelas APIs. |
| ID token | Expiração do token de identidade. |
| Refresh token | Vida máxima da família rotacionada. |
| Sessão SSO | Duração da sessão OIDC. |
| Sobreposição de secrets | Tempo em que o client secret anterior continua aceito após rotação. |

TTL alterado vale para emissões futuras. APIs que validam JWT localmente aceitam um token até seu `exp`.

## 8. Auditoria

A retenção determina quantos dias os eventos permanecem no banco. A limpeza periódica remove registros expirados automaticamente. Veja [Auditoria](auditoria).

## 9. Acessos e chaves

Os atalhos finais abrem:

- permissões administrativas;
- listagem de clients e suas roles;
- chaves de assinatura e JWKS.

Chaves privadas RSA ficam cifradas no banco. Ao rotacionar, a chave anterior permanece no JWKS durante a janela necessária para validar tokens ainda ativos. Preserve `KEY_ENCRYPTION_SECRET`; trocá-lo sem recriptografia torna chaves privadas, TOTP e outros dados cifrados ilegíveis.
