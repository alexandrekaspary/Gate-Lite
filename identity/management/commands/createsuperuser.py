from django.conf import settings
from django.contrib.auth.management.commands import createsuperuser


class Command(createsuperuser.Command):
    """Use the project default instead of the operating-system username."""

    def handle(self, *args, **options):
        original_default = createsuperuser.get_default_username
        createsuperuser.get_default_username = lambda database: settings.DEFAULT_SUPERUSER_USERNAME
        try:
            return super().handle(*args, **options)
        finally:
            createsuperuser.get_default_username = original_default
