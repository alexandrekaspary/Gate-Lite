from django.core.management.base import BaseCommand
from identity.cleanup import run_cleanup

class Command(BaseCommand):
    help = (
        "Remove artefatos OIDC expirados e eventos de auditoria além da retenção configurada. "
        "A limpeza também roda automaticamente em segundo plano a cada 24h; use este comando "
        "apenas para forçar uma execução imediata."
    )
    def handle(self,*args,**options):
        counts=run_cleanup()
        self.stdout.write(self.style.SUCCESS("Limpeza concluída: "+", ".join(f"{k}={v}" for k,v in counts.items())))
