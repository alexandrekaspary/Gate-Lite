import os
import sys
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
TESTING = len(sys.argv) > 1 and sys.argv[1] == "test"


def load_dotenv(path: Path) -> None:
    """Carrega um arquivo .env sem substituir variáveis já exportadas."""
    if not path.is_file():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


# Permite executar os comandos Django localmente com as variáveis do .env.
# Variáveis exportadas pelo sistema ou pelo container sempre têm precedência.
if not TESTING:
    load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-change-me-before-production")
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
if not DEBUG and "DJANGO_SECRET_KEY" not in os.environ:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY é obrigatório em produção.")
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = [v for v in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if v]

INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles",
    "identity",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware", "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware", "django.middleware.csrf.CsrfViewMiddleware",
    "identity.middleware.OIDCCORSMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware", "identity.middleware.PasswordChangeRequiredMiddleware", "identity.middleware.MFAEnforcementMiddleware", "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "gatelite.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "gatelite.wsgi.application"
# Banco de dados. DB_ENGINE aceita "sqlite" (padrão) ou "postgres".
# A suíte de testes sempre usa SQLite, independentemente do ambiente.
DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite").strip().lower()
if TESTING or DB_ENGINE == "sqlite":
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
elif DB_ENGINE in ("postgres", "postgresql"):
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "gatelite"),
        "USER": os.environ.get("DB_USER", "gatelite"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "CONN_MAX_AGE": int(os.environ.get("DB_CONN_MAX_AGE", "60")),
    }}
else:
    raise ImproperlyConfigured(f"DB_ENGINE inválido: {DB_ENGINE!r}. Use 'sqlite' ou 'postgres'.")
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "identity.validators.ConfigurablePasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "pt-br"
TIME_ZONE = "America/Sao_Paulo"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "account"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0" if DEBUG else "1") == "1"
CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", "0" if DEBUG else "1") == "1"
SECURE_SSL_REDIRECT = os.environ.get("DJANGO_SECURE_SSL_REDIRECT", "0" if DEBUG else "1") == "1"
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "0" if DEBUG else "31536000"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# Ative somente atrás de um proxy reverso que SEMPRE define X-Forwarded-Proto;
# sem isso o Django não reconhece HTTPS terminado no proxy (loop de redirect,
# cookies seguros ausentes e next= http aceito).
if os.environ.get("TRUST_PROXY_SSL_HEADER", "0") == "1":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8000").rstrip("/")
KEY_ENCRYPTION_SECRET = os.environ.get("KEY_ENCRYPTION_SECRET", SECRET_KEY)
if not DEBUG and "KEY_ENCRYPTION_SECRET" not in os.environ:
    raise ImproperlyConfigured("KEY_ENCRYPTION_SECRET é obrigatório em produção.")

# E-mail transacional. Sem um host SMTP em produção, os envios são descartados
# para que a criação de contas e outros fluxos não tentem conectar a localhost.
_SMTP_EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
_configured_email_backend = os.environ.get(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend" if DEBUG else _SMTP_EMAIL_BACKEND,
)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "").strip()
EMAIL_ENABLED = os.environ.get(
    "EMAIL_ENABLED",
    "1" if _configured_email_backend != _SMTP_EMAIL_BACKEND or EMAIL_HOST else "0",
) == "1"
EMAIL_BACKEND = (
    _configured_email_backend
    if EMAIL_ENABLED
    else "django.core.mail.backends.dummy.EmailBackend"
)
EMAIL_PORT = int(os.environ.get("EMAIL_PORT") or "587")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "1") == "1"
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "0") == "1"
if EMAIL_ENABLED and _configured_email_backend == _SMTP_EMAIL_BACKEND and EMAIL_USE_TLS and EMAIL_USE_SSL:
    raise ImproperlyConfigured("EMAIL_USE_TLS e EMAIL_USE_SSL não podem ser ativados juntos.")
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT") or "10")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "GateLite <no-reply@localhost>")
SERVER_EMAIL = os.environ.get("SERVER_EMAIL", DEFAULT_FROM_EMAIL)
# As validades de confirmação de e-mail e de recuperação de senha são
# persistidas em SecurityPolicy e editadas no console (Configurações).
