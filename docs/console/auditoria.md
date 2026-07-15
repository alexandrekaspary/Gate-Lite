# Auditoria

A tela registra eventos de autenticação e administração com data, ação, ator, alvo, metadados e IP. Exige `Pode visualizar o log de auditoria`.

## Filtros

- busca por ação, usuário, alvo ou IP;
- ação exata;
- intervalo de datas;
- paginação de 50 eventos, do mais recente para o mais antigo.

Eventos incluem login bem-sucedido ou falho, bloqueio, usuários, grupos, clients, e-mail, senha, 2FA, configurações, chaves e limpeza.

## IP atrás de load balancer

Sem configuração extra, o GateLite registra `REMOTE_ADDR`, que normalmente será o load balancer. Para usar o IP encaminhado:

```env
TRUST_X_FORWARDED_FOR=1
TRUSTED_PROXY_COUNT=1
```

Use a quantidade real de proxies confiáveis. O GateLite escolhe o endereço da direita para a esquerda na cadeia `X-Forwarded-For`, reduzindo o risco de spoofing. Não habilite se clientes puderem acessar a aplicação diretamente sem passar pelo proxy confiável.

## Retenção

O prazo é configurado em Configurações. A limpeza automática roda de forma oportunista a cada 24 horas. Para executar imediatamente:

```bash
python manage.py cleanup_identity
```
