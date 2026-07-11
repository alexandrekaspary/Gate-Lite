from django.contrib.auth.hashers import make_password
from django.db import migrations


def create_initial_admin(apps, schema_editor):
    User = apps.get_model("auth", "User")
    UserSecurityState = apps.get_model("identity", "UserSecurityState")
    admin, created = User.objects.get_or_create(
        username="admin",
        defaults={
            "password": make_password("123456"),
            "is_active": True,
            "is_staff": True,
            "is_superuser": True,
        },
    )
    if not created:
        return

    state, _ = UserSecurityState.objects.get_or_create(user=admin)
    state.must_change_password = True
    state.save(update_fields=["must_change_password", "updated_at"])


class Migration(migrations.Migration):

    dependencies = [
        ("identity", "0017_usersecuritystate_must_change_password"),
    ]

    operations = [
        migrations.RunPython(create_initial_admin, migrations.RunPython.noop),
    ]
