import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class ConfigurablePasswordValidator:
    def validate(self, password, user=None):
        from .models import SecurityPolicy
        policy=SecurityPolicy.load(); errors=[]
        if len(password) < policy.password_min_length: errors.append(f"A senha deve ter ao menos {policy.password_min_length} caracteres.")
        if policy.password_require_uppercase and not re.search(r"[A-Z]",password): errors.append("Inclua uma letra maiúscula.")
        if policy.password_require_lowercase and not re.search(r"[a-z]",password): errors.append("Inclua uma letra minúscula.")
        if policy.password_require_number and not re.search(r"\d",password): errors.append("Inclua um número.")
        if policy.password_require_special and not re.search(r"[^A-Za-z0-9]",password): errors.append("Inclua um caractere especial.")
        if errors: raise ValidationError(errors)
    def get_help_text(self): return "A senha deve atender à política de segurança configurada."
