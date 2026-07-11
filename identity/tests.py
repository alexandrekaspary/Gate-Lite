import base64
import hashlib
from urllib.parse import parse_qs, unquote, urlparse

import jwt
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import Group, Permission, User
from django.test import TestCase, override_settings
from django.utils import timezone
from unittest.mock import patch

from .crypto import decrypt_value, private_pem
from .forms import ClientForm, ClientRoleForm, GroupForm
from .mfa import (
    hash_recovery_codes,
    matching_counter,
    provisioning_uri,
    totp_code,
    verify_mfa,
)
from .models import (
    AuditEvent,
    ClientRole,
    ClientScopeAssignment,
    ClientURI,
    ClientWebOrigin,
    MFAChallenge,
    OIDCClient,
    OIDCSession,
    OIDCScope,
    RefreshToken,
    RevokedAccessToken,
    SecurityPolicy,
    ServiceAccountRoleAssignment,
    SigningKey,
    UserMFA,
    UserSecurityState,
)
from .oidc import issue_tokens


ISSUER = "http://testserver"
DEFAULT_SCOPES = (
    "openid",
    "profile",
    "email",
    "groups",
    "permissions",
    "offline_access",
    "api.read",
)


@override_settings(OIDC_ISSUER=ISSUER)
class OIDCTestCase(TestCase):
    """Factories and protocol helpers shared by the OIDC integration tests."""

    def make_client(
        self,
        client_id,
        *,
        client_type=OIDCClient.ClientType.CONFIDENTIAL,
        application_type=None,
        auth_method=None,
        secret=None,
        redirects=None,
        origins=(),
        scopes=DEFAULT_SCOPES,
        **overrides,
    ):
        public = client_type == OIDCClient.ClientType.PUBLIC
        application_type = application_type or (
            OIDCClient.ApplicationType.SPA if public else OIDCClient.ApplicationType.WEB
        )
        auth_method = auth_method or (
            OIDCClient.AuthMethod.NONE if public else OIDCClient.AuthMethod.BASIC
        )
        values = {
            "name": client_id.replace("-", " ").title(),
            "client_id": client_id,
            "application_type": application_type,
            "client_type": client_type,
            "token_endpoint_auth_method": auth_method,
            "require_pkce": public,
            "authorization_code_enabled": True,
            "refresh_token_enabled": True,
            "client_credentials_enabled": False,
            "access_policy": OIDCClient.AccessPolicy.OPEN,
            "is_active": True,
        }
        values.update(overrides)
        client = OIDCClient.objects.create(**values)

        if redirects is None:
            redirects = (f"https://{client_id}.example/callback",)
        for uri in redirects:
            ClientURI.objects.create(client=client, kind=ClientURI.Kind.REDIRECT, uri=uri)
        for origin in origins:
            ClientWebOrigin.objects.create(client=client, origin=origin)
        for scope_name in scopes:
            scope, _ = OIDCScope.objects.get_or_create(name=scope_name)
            ClientScopeAssignment.objects.get_or_create(
                client=client,
                scope=scope,
                defaults={"is_default": scope_name in {"openid", "profile", "email"}},
            )

        if not public:
            secret = secret or f"secret-for-{client_id}"
            client.set_secret(secret)
            if not hasattr(self, "client_secrets"):
                self.client_secrets = {}
            self.client_secrets[client.client_id] = secret
        return client

    @staticmethod
    def pkce(verifier=None):
        verifier = verifier or "v" * 64
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        return verifier, challenge

    def authorization_request(
        self,
        client,
        user,
        *,
        scope="openid",
        audience=None,
        redirect_uri=None,
        verifier=None,
        include_pkce=None,
        method="S256",
        state="test-state",
        nonce="test-nonce",
    ):
        self.client.force_login(user)
        redirect_uri = redirect_uri or client.uri_list()[0]
        params = {
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "nonce": nonce,
        }
        if audience:
            params["audience"] = audience.client_id if isinstance(audience, OIDCClient) else audience
        if include_pkce is None:
            include_pkce = client.client_type == OIDCClient.ClientType.PUBLIC or client.require_pkce
        if include_pkce:
            verifier, challenge = self.pkce(verifier)
            params.update(code_challenge=challenge, code_challenge_method=method)
        response = self.client.get("/oidc/authorize/", params)
        query = parse_qs(urlparse(response.url).query) if response.status_code == 302 else {}
        return response, query, verifier

    def post_as_client(self, path, client, data, *, method=None, secret=None):
        data = dict(data)
        method = method or client.token_endpoint_auth_method
        secret = secret if secret is not None else getattr(self, "client_secrets", {}).get(client.client_id, "")
        headers = {}
        if method == OIDCClient.AuthMethod.BASIC:
            raw = base64.b64encode(f"{client.client_id}:{secret}".encode()).decode()
            headers["HTTP_AUTHORIZATION"] = f"Basic {raw}"
        elif method == OIDCClient.AuthMethod.POST:
            data.update(client_id=client.client_id, client_secret=secret)
        else:
            data["client_id"] = client.client_id
        return self.client.post(path, data, **headers)

    def exchange_code(self, client, code, redirect_uri, *, verifier=None, method=None, secret=None):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if verifier is not None:
            data["code_verifier"] = verifier
        return self.post_as_client(
            "/oidc/token/", client, data, method=method, secret=secret
        )

    def tokens_via_code(self, client, user, *, scope="openid", audience=None):
        response, query, verifier = self.authorization_request(
            client, user, scope=scope, audience=audience
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("code", query, query)
        response = self.exchange_code(
            client,
            query["code"][0],
            client.uri_list()[0],
            verifier=verifier,
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def decode_without_verification(self, token):
        return jwt.decode(token, options={"verify_signature": False})


class ClientAuthenticationTests(OIDCTestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="Alice-password-1")

    def test_public_client_requires_s256_and_exchanges_without_a_secret(self):
        public = self.make_client(
            "spa",
            client_type=OIDCClient.ClientType.PUBLIC,
            # Endpoint security must not depend only on model.clean() having run.
            require_pkce=False,
        )
        self.assertFalse(public.secrets.exists())

        response, query, _ = self.authorization_request(
            public, self.user, include_pkce=False
        )
        self.assertEqual(query["error"], ["invalid_request"])

        response, query, _ = self.authorization_request(
            public,
            self.user,
            include_pkce=True,
            method="plain",
        )
        self.assertEqual(query["error"], ["invalid_request"])

        verifier = "correct-verifier-" + "x" * 48
        response, query, _ = self.authorization_request(
            public, self.user, include_pkce=True, verifier=verifier
        )
        code = query["code"][0]

        with_secret = self.exchange_code(
            public,
            code,
            public.uri_list()[0],
            verifier=verifier,
            method=OIDCClient.AuthMethod.POST,
            secret="a-public-client-must-not-have-this",
        )
        self.assertEqual(with_secret.status_code, 401)
        self.assertEqual(with_secret.json()["error"], "invalid_client")

        wrong_verifier = self.exchange_code(
            public, code, public.uri_list()[0], verifier="z" * 64
        )
        self.assertEqual(wrong_verifier.status_code, 400)
        self.assertEqual(wrong_verifier.json()["error"], "invalid_grant")

        exchanged = self.exchange_code(
            public, code, public.uri_list()[0], verifier=verifier
        )
        self.assertEqual(exchanged.status_code, 200, exchanged.content)
        self.assertIn("access_token", exchanged.json())

    def test_confidential_clients_enforce_basic_or_post_exactly(self):
        basic = self.make_client(
            "basic-service",
            application_type=OIDCClient.ApplicationType.SERVICE,
            auth_method=OIDCClient.AuthMethod.BASIC,
            secret="basic-secret",
            redirects=(),
            authorization_code_enabled=False,
            refresh_token_enabled=False,
            client_credentials_enabled=True,
        )
        post = self.make_client(
            "post-service",
            application_type=OIDCClient.ApplicationType.SERVICE,
            auth_method=OIDCClient.AuthMethod.POST,
            secret="post-secret",
            redirects=(),
            authorization_code_enabled=False,
            refresh_token_enabled=False,
            client_credentials_enabled=True,
        )
        self.assertNotEqual(basic.secrets.get().secret_hash, "basic-secret")
        self.assertTrue(basic.check_secret("basic-secret"))

        basic_ok = self.post_as_client(
            "/oidc/token/",
            basic,
            {"grant_type": "client_credentials", "scope": "api.read"},
        )
        self.assertEqual(basic_ok.status_code, 200, basic_ok.content)
        basic_via_post = self.post_as_client(
            "/oidc/token/",
            basic,
            {"grant_type": "client_credentials", "scope": "api.read"},
            method=OIDCClient.AuthMethod.POST,
        )
        self.assertEqual(basic_via_post.status_code, 401)
        basic_without_secret = self.post_as_client(
            "/oidc/token/",
            basic,
            {"grant_type": "client_credentials", "scope": "api.read"},
            method=OIDCClient.AuthMethod.NONE,
        )
        self.assertEqual(basic_without_secret.status_code, 401)

        post_ok = self.post_as_client(
            "/oidc/token/",
            post,
            {"grant_type": "client_credentials", "scope": "api.read"},
        )
        self.assertEqual(post_ok.status_code, 200, post_ok.content)
        post_via_basic = self.post_as_client(
            "/oidc/token/",
            post,
            {"grant_type": "client_credentials", "scope": "api.read"},
            method=OIDCClient.AuthMethod.BASIC,
        )
        self.assertEqual(post_via_basic.status_code, 401)


class RoleAndAudienceTests(OIDCTestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="Alice-password-1")

    def test_direct_and_group_roles_are_unioned_deduplicated_and_isolated(self):
        api = self.make_client(
            "billing-api",
            application_type=OIDCClient.ApplicationType.RESOURCE,
            authorization_code_enabled=False,
            redirects=(),
            access_policy=OIDCClient.AccessPolicy.RESTRICTED,
        )
        other = self.make_client(
            "support-api",
            application_type=OIDCClient.ApplicationType.RESOURCE,
            authorization_code_enabled=False,
            redirects=(),
        )
        group = Group.objects.create(name="finance")
        self.user.groups.add(group)

        approve = ClientRole.objects.create(client=api, name="approve")
        view = ClientRole.objects.create(client=api, name="view")
        foreign = ClientRole.objects.create(client=other, name="support-admin")
        approve.users.add(self.user)
        approve.groups.add(group)
        view.groups.add(group)
        foreign.users.add(self.user)

        self.assertTrue(api.user_has_access(self.user))
        self.assertEqual(api.effective_role_names(self.user), ["approve", "view"])
        tokens = issue_tokens(self.user, api, "openid groups", include_refresh=False)
        claims = self.decode_without_verification(tokens["access_token"])
        self.assertEqual(claims["roles"], ["approve", "view"])
        self.assertEqual(
            claims["resource_access"],
            {"billing-api": {"roles": ["approve", "view"]}},
        )
        self.assertNotIn("support-admin", claims["roles"])

    def test_restricted_client_denies_unassigned_user_and_accepts_each_assignment_type(self):
        restricted = self.make_client(
            "restricted-spa",
            client_type=OIDCClient.ClientType.PUBLIC,
            access_policy=OIDCClient.AccessPolicy.RESTRICTED,
        )

        _, query, _ = self.authorization_request(restricted, self.user)
        self.assertEqual(query["error"], ["access_denied"])

        allowed_group = Group.objects.create(name="allowed")
        restricted.allowed_groups.add(allowed_group)
        self.user.groups.add(allowed_group)
        self.assertTrue(restricted.user_has_access(self.user))
        _, query, _ = self.authorization_request(restricted, self.user)
        self.assertIn("code", query)

        self.user.groups.remove(allowed_group)
        restricted.allowed_users.add(self.user)
        self.assertTrue(restricted.user_has_access(self.user))

        restricted.allowed_users.remove(self.user)
        direct_role = ClientRole.objects.create(client=restricted, name="direct-access")
        direct_role.users.add(self.user)
        self.assertTrue(restricted.user_has_access(self.user))

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assertFalse(restricted.user_has_access(self.user))

    def test_spa_can_request_authorized_api_audience_only(self):
        spa = self.make_client("portal", client_type=OIDCClient.ClientType.PUBLIC)
        api = self.make_client(
            "portal-api",
            application_type=OIDCClient.ApplicationType.RESOURCE,
            authorization_code_enabled=False,
            redirects=(),
            access_policy=OIDCClient.AccessPolicy.RESTRICTED,
        )
        forbidden_api = self.make_client(
            "forbidden-api",
            application_type=OIDCClient.ApplicationType.RESOURCE,
            authorization_code_enabled=False,
            redirects=(),
        )
        spa.allowed_audiences.add(api)
        api_role = ClientRole.objects.create(client=api, name="invoice-read")
        spa_role = ClientRole.objects.create(client=spa, name="portal-user")
        api_role.users.add(self.user)
        spa_role.users.add(self.user)

        tokens = self.tokens_via_code(
            spa, self.user, scope="openid profile", audience=api
        )
        access = self.decode_without_verification(tokens["access_token"])
        identity = self.decode_without_verification(tokens["id_token"])
        self.assertEqual(access["aud"], "portal-api")
        self.assertEqual(access["azp"], "portal")
        self.assertEqual(access["roles"], ["invoice-read"])
        self.assertEqual(access["resource_access"], {"portal-api": {"roles": ["invoice-read"]}})
        self.assertEqual(identity["aud"], "portal")
        self.assertEqual(identity["azp"], "portal")
        self.assertEqual(identity["roles"], ["portal-user"])

        userinfo = self.client.get(
            "/oidc/userinfo/", HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}"
        )
        self.assertEqual(userinfo.status_code, 200, userinfo.content)
        self.assertEqual(userinfo.json()["roles"], ["invoice-read"])

        _, query, _ = self.authorization_request(
            spa, self.user, audience=forbidden_api
        )
        self.assertEqual(query["error"], ["invalid_target"])

    def test_client_credentials_uses_service_account_assignments_for_target_api(self):
        service = self.make_client(
            "report-worker",
            application_type=OIDCClient.ApplicationType.SERVICE,
            redirects=(),
            authorization_code_enabled=False,
            refresh_token_enabled=False,
            client_credentials_enabled=True,
        )
        api = self.make_client(
            "reports-api",
            application_type=OIDCClient.ApplicationType.RESOURCE,
            redirects=(),
            authorization_code_enabled=False,
        )
        unauthorized_api = self.make_client(
            "other-api",
            application_type=OIDCClient.ApplicationType.RESOURCE,
            redirects=(),
            authorization_code_enabled=False,
        )
        other_service = self.make_client(
            "other-report-worker",
            application_type=OIDCClient.ApplicationType.SERVICE,
            redirects=(),
            authorization_code_enabled=False,
            refresh_token_enabled=False,
            client_credentials_enabled=True,
        )
        service.allowed_audiences.add(api)
        generate = ClientRole.objects.create(client=api, name="generate-report")
        expired = ClientRole.objects.create(client=api, name="expired-role")
        ServiceAccountRoleAssignment.objects.create(role=generate, service_client=service)
        ServiceAccountRoleAssignment.objects.create(
            role=expired,
            service_client=service,
            expires_at=timezone.now() - timezone.timedelta(days=1),
        )
        # An active assignment of the same role to another service must not
        # reactivate this service's expired assignment.
        ServiceAccountRoleAssignment.objects.create(
            role=expired,
            service_client=other_service,
        )

        response = self.post_as_client(
            "/oidc/token/",
            service,
            {
                "grant_type": "client_credentials",
                "scope": "api.read",
                "audience": api.client_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertNotIn("id_token", body)
        self.assertNotIn("refresh_token", body)
        claims = self.decode_without_verification(body["access_token"])
        self.assertEqual(claims["sub"], "client:report-worker")
        self.assertEqual(claims["aud"], "reports-api")
        self.assertEqual(claims["azp"], "report-worker")
        self.assertEqual(claims["roles"], ["generate-report"])

        unauthorized = self.post_as_client(
            "/oidc/token/",
            service,
            {
                "grant_type": "client_credentials",
                "scope": "api.read",
                "audience": unauthorized_api.client_id,
            },
        )
        self.assertEqual(unauthorized.status_code, 400)
        self.assertEqual(unauthorized.json()["error"], "invalid_target")


class RoleManagementFormTests(OIDCTestCase):
    def test_group_and_role_forms_manage_users_groups_and_service_accounts(self):
        user = User.objects.create_user("member")
        group = Group.objects.create(name="operators")
        api_one = self.make_client("api-one", redirects=())
        api_two = self.make_client("api-two", redirects=())
        service = self.make_client(
            "service-account",
            application_type=OIDCClient.ApplicationType.SERVICE,
            redirects=(),
            authorization_code_enabled=False,
            client_credentials_enabled=True,
        )
        role_one = ClientRole.objects.create(client=api_one, name="read")
        role_two = ClientRole.objects.create(client=api_two, name="write")

        group_form = GroupForm(
            {
                "name": group.name,
                "users": [user.pk],
                "client_roles": [role_one.pk, role_two.pk],
                "permissions": [],
            },
            instance=group,
        )
        self.assertTrue(group_form.is_valid(), group_form.errors)
        group_form.save()
        self.assertEqual(list(group.user_set.all()), [user])
        self.assertEqual(set(group.oidc_client_roles.all()), {role_one, role_two})

        direct_user = User.objects.create_user("direct")
        direct_group = Group.objects.create(name="direct-group")
        role_form = ClientRoleForm(
            {
                "client": api_one.pk,
                "name": "admin",
                "description": "Full API access",
                "users": [direct_user.pk],
                "groups": [direct_group.pk],
                "service_clients": [service.pk],
            }
        )
        self.assertTrue(role_form.is_valid(), role_form.errors)
        role = role_form.save()
        self.assertEqual(list(role.users.all()), [direct_user])
        self.assertEqual(list(role.groups.all()), [direct_group])
        self.assertEqual(list(role.service_clients.all()), [service])


class TokenLifecycleTests(OIDCTestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="Alice-password-1")

    def test_refresh_rotation_and_replay_revoke_the_whole_family_and_session(self):
        spa = self.make_client("refresh-spa", client_type=OIDCClient.ClientType.PUBLIC)
        tokens = self.tokens_via_code(
            spa, self.user, scope="openid offline_access"
        )
        old_raw = tokens["refresh_token"]
        old = RefreshToken.objects.get(
            token_hash=hashlib.sha256(old_raw.encode()).hexdigest()
        )

        rotated_response = self.post_as_client(
            "/oidc/token/",
            spa,
            {"grant_type": "refresh_token", "refresh_token": old_raw},
        )
        self.assertEqual(rotated_response.status_code, 200, rotated_response.content)
        new_raw = rotated_response.json()["refresh_token"]
        self.assertNotEqual(new_raw, old_raw)
        new = RefreshToken.objects.get(
            token_hash=hashlib.sha256(new_raw.encode()).hexdigest()
        )
        old.refresh_from_db()
        self.assertIsNotNone(old.revoked_at)
        self.assertEqual(new.parent, old)
        self.assertEqual(new.family_id, old.family_id)
        self.assertEqual(new.expires_at, old.expires_at)

        replay = self.post_as_client(
            "/oidc/token/",
            spa,
            {"grant_type": "refresh_token", "refresh_token": old_raw},
        )
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()["error"], "invalid_grant")
        old.refresh_from_db()
        new.refresh_from_db()
        self.assertIsNotNone(old.reuse_detected_at)
        self.assertIsNotNone(new.revoked_at)
        self.assertFalse(new.oidc_session.is_active())
        self.assertFalse(
            RefreshToken.objects.filter(
                family_id=old.family_id, revoked_at__isnull=True
            ).exists()
        )

        descendant_reuse = self.post_as_client(
            "/oidc/token/",
            spa,
            {"grant_type": "refresh_token", "refresh_token": new_raw},
        )
        self.assertEqual(descendant_reuse.status_code, 400)

    def test_revocation_and_introspection_cover_access_and_refresh_tokens(self):
        backend = self.make_client(
            "backend",
            require_pkce=False,
            auth_method=OIDCClient.AuthMethod.BASIC,
        )
        other = self.make_client(
            "other-backend",
            require_pkce=False,
            auth_method=OIDCClient.AuthMethod.BASIC,
        )
        tokens = self.tokens_via_code(
            backend, self.user, scope="openid offline_access"
        )
        access = tokens["access_token"]
        refresh = tokens["refresh_token"]
        access_jti = self.decode_without_verification(access)["jti"]

        access_before = self.post_as_client(
            "/oidc/introspect/", backend, {"token": access}
        )
        refresh_before = self.post_as_client(
            "/oidc/introspect/", backend, {"token": refresh}
        )
        id_token = self.post_as_client(
            "/oidc/introspect/", backend, {"token": tokens["id_token"]}
        )
        self.assertTrue(access_before.json()["active"])
        self.assertEqual(access_before.json()["token_type"], "access_token")
        self.assertTrue(refresh_before.json()["active"])
        self.assertEqual(refresh_before.json()["token_type"], "refresh_token")
        self.assertFalse(id_token.json()["active"])
        self.assertEqual(access_before["Cache-Control"], "no-store")

        # A different client gets an idempotent response but cannot revoke the token.
        foreign_revoke = self.post_as_client(
            "/oidc/revoke/", other, {"token": access}
        )
        self.assertEqual(foreign_revoke.status_code, 200)
        self.assertFalse(RevokedAccessToken.objects.filter(pk=access_jti).exists())
        still_active = self.post_as_client(
            "/oidc/introspect/", backend, {"token": access}
        )
        self.assertTrue(still_active.json()["active"])

        revoke_access = self.post_as_client(
            "/oidc/revoke/", backend, {"token": access}
        )
        self.assertEqual(revoke_access.status_code, 200)
        self.assertEqual(revoke_access.json(), {})
        self.assertEqual(revoke_access["Cache-Control"], "no-store")
        self.assertTrue(RevokedAccessToken.objects.filter(pk=access_jti).exists())
        access_after = self.post_as_client(
            "/oidc/introspect/", backend, {"token": access}
        )
        self.assertFalse(access_after.json()["active"])

        revoke_refresh = self.post_as_client(
            "/oidc/revoke/", backend, {"token": refresh}
        )
        self.assertEqual(revoke_refresh.status_code, 200)
        refresh_after = self.post_as_client(
            "/oidc/introspect/", backend, {"token": refresh}
        )
        self.assertFalse(refresh_after.json()["active"])
        refresh_record = RefreshToken.objects.get(
            token_hash=hashlib.sha256(refresh.encode()).hexdigest()
        )
        self.assertIsNotNone(refresh_record.revoked_at)
        self.assertFalse(refresh_record.oidc_session.is_active())


class CORSAndURIValidationTests(OIDCTestCase):
    def test_cors_is_exact_and_only_active_configured_origins_are_echoed(self):
        self.make_client("spa", origins=("https://app.example",))
        self.make_client(
            "inactive-spa", origins=("https://inactive.example",), is_active=False
        )

        allowed = self.client.options(
            "/oidc/token/", HTTP_ORIGIN="https://app.example"
        )
        self.assertEqual(allowed.status_code, 204)
        self.assertEqual(allowed["Access-Control-Allow-Origin"], "https://app.example")
        self.assertIn("Authorization", allowed["Access-Control-Allow-Headers"])
        self.assertIn("Origin", allowed["Vary"])

        denied = self.client.options(
            "/oidc/token/", HTTP_ORIGIN="https://app.example.evil.test"
        )
        self.assertNotEqual(denied.status_code, 204)
        self.assertNotIn("Access-Control-Allow-Origin", denied)

        inactive = self.client.options(
            "/oidc/token/", HTTP_ORIGIN="https://inactive.example"
        )
        self.assertNotEqual(inactive.status_code, 204)
        self.assertNotIn("Access-Control-Allow-Origin", inactive)

        jwks = self.client.get(
            "/oidc/jwks/", HTTP_ORIGIN="https://app.example"
        )
        self.assertEqual(jwks["Access-Control-Allow-Origin"], "https://app.example")

    @staticmethod
    def client_form_data(**overrides):
        data = {
            "name": "Browser app",
            "client_id": "browser-app",
            "application_type": OIDCClient.ApplicationType.SPA,
            "client_type": OIDCClient.ClientType.PUBLIC,
            "token_endpoint_auth_method": OIDCClient.AuthMethod.POST,
            "authorization_code_enabled": "on",
            "refresh_token_enabled": "on",
            "client_credentials_enabled": "on",
            "access_policy": OIDCClient.AccessPolicy.OPEN,
            "is_active": "on",
            "redirect_uris": "https://app.example/callback\nhttp://localhost:5173/callback",
            "post_logout_redirect_uris": "https://app.example/signed-out",
            "allowed_origins": "https://app.example/\nhttp://localhost:5173",
            "scopes": "openid profile email custom.scope",
            "allowed_audiences": [],
            "allowed_groups": [],
            "allowed_users": [],
        }
        data.update(overrides)
        return data

    def test_client_form_enforces_invariants_and_persists_normalized_configuration(self):
        form = ClientForm(self.client_form_data())
        self.assertTrue(form.is_valid(), form.errors)
        client = form.save()
        self.assertEqual(client.token_endpoint_auth_method, OIDCClient.AuthMethod.NONE)
        self.assertTrue(client.require_pkce)
        self.assertFalse(client.client_credentials_enabled)
        self.assertEqual(
            set(client.uri_list()),
            {
                "https://app.example/callback",
                "http://localhost:5173/callback",
            },
        )
        self.assertEqual(
            client.uri_list("post_logout_redirect_uris"),
            ["https://app.example/signed-out"],
        )
        self.assertEqual(
            set(client.origin_list()),
            {"https://app.example", "http://localhost:5173"},
        )
        self.assertEqual(
            set(client.scope_names()),
            {"openid", "profile", "email", "custom.scope"},
        )

    def test_client_form_rejects_unsafe_uris_origins_and_invalid_type_combinations(self):
        invalid_cases = (
            (
                {"client_id": "remote-http", "redirect_uris": "http://example.com/callback"},
                "redirect_uris",
            ),
            (
                {
                    "client_id": "credential-uri",
                    "redirect_uris": "https://user:password@app.example/callback",
                },
                "redirect_uris",
            ),
            (
                {
                    "client_id": "fragment-uri",
                    "redirect_uris": "https://app.example/callback#fragment",
                },
                "redirect_uris",
            ),
            (
                {"client_id": "origin-path", "allowed_origins": "https://app.example/path"},
                "allowed_origins",
            ),
            (
                {"client_id": "spa-custom", "redirect_uris": "com.example.app:/callback"},
                "redirect_uris",
            ),
            (
                {
                    "client_id": "public-service",
                    "application_type": OIDCClient.ApplicationType.SERVICE,
                },
                "client_type",
            ),
            (
                {
                    "client_id": "confidential-none",
                    "application_type": OIDCClient.ApplicationType.WEB,
                    "client_type": OIDCClient.ClientType.CONFIDENTIAL,
                    "token_endpoint_auth_method": OIDCClient.AuthMethod.NONE,
                },
                "__all__",
            ),
        )
        for changes, expected_field in invalid_cases:
            with self.subTest(changes=changes):
                form = ClientForm(self.client_form_data(**changes))
                self.assertFalse(form.is_valid())
                self.assertIn(expected_field, form.errors, form.errors)

        native = ClientForm(
            self.client_form_data(
                client_id="native-app",
                application_type=OIDCClient.ApplicationType.NATIVE,
                redirect_uris="com.example.app:/oauth2redirect",
                allowed_origins="",
            )
        )
        self.assertTrue(native.is_valid(), native.errors)

    def test_duplicate_normalized_values_do_not_crash_or_create_duplicate_rows(self):
        form = ClientForm(
            self.client_form_data(
                client_id="duplicates",
                redirect_uris="https://app.example/callback\nhttps://app.example/callback",
                allowed_origins="https://app.example/\nhttps://app.example",
                scopes="openid profile openid profile",
            )
        )
        self.assertTrue(form.is_valid(), form.errors)
        client = form.save()
        self.assertEqual(
            ClientURI.objects.filter(client=client, kind=ClientURI.Kind.REDIRECT).count(),
            1,
        )
        self.assertEqual(ClientWebOrigin.objects.filter(client=client).count(), 1)
        self.assertEqual(ClientScopeAssignment.objects.filter(client=client).count(), 2)


class ConsoleRBACTests(TestCase):
    @staticmethod
    def permission(codename):
        return Permission.objects.get(
            content_type__app_label="identity", codename=codename
        )

    def test_console_permissions_are_independent_and_protect_mutations(self):
        group = Group.objects.create(name="must-survive")
        operator = User.objects.create_user(
            "operator", password="Operator-password-1", is_staff=True
        )
        self.client.force_login(operator)
        self.assertEqual(self.client.get("/").status_code, 403)
        self.assertEqual(self.client.get("/console/users/").status_code, 403)

        operator.user_permissions.add(self.permission("view_identity_console"))
        self.client.force_login(operator)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/console/users/").status_code, 403)

        operator.user_permissions.add(self.permission("manage_users"))
        self.client.force_login(operator)
        self.assertEqual(
            self.client.get("/console/users/?q=operator&status=active").status_code,
            200,
        )
        self.assertEqual(self.client.get("/console/groups/").status_code, 403)
        denied_delete = self.client.post(
            f"/console/groups/{group.pk}/delete/"
        )
        self.assertEqual(denied_delete.status_code, 403)
        self.assertTrue(Group.objects.filter(pk=group.pk).exists())

    def test_manage_clients_covers_clients_and_roles_and_superuser_has_full_access(self):
        client_manager = User.objects.create_user(
            "client-manager", password="Client-manager-password-1"
        )
        client_manager.user_permissions.add(self.permission("manage_clients"))
        self.client.force_login(client_manager)
        self.assertEqual(self.client.get("/console/clients/").status_code, 200)
        self.assertEqual(self.client.get("/console/roles/?q=read").status_code, 200)
        self.assertEqual(self.client.get("/console/users/").status_code, 403)
        self.assertEqual(self.client.get("/console/settings/").status_code, 403)

        admin = User.objects.create_superuser(
            "root", email="root@example.com", password="Root-password-1"
        )
        self.client.force_login(admin)
        for url in (
            "/",
            "/console/users/",
            "/console/groups/",
            "/console/clients/",
            "/console/roles/",
            "/console/permissions/",
            "/console/settings/",
            "/console/keys/",
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_console_creates_public_and_confidential_clients_with_correct_credentials(self):
        admin = User.objects.create_superuser(
            "creator", email="creator@example.com", password="Creator-password-1"
        )
        self.client.force_login(admin)
        common = {
            "authorization_code_enabled": "on",
            "refresh_token_enabled": "on",
            "access_policy": OIDCClient.AccessPolicy.OPEN,
            "is_active": "on",
            "redirect_uris": "https://app.example/callback",
            "post_logout_redirect_uris": "https://app.example/signed-out",
            "allowed_origins": "https://app.example",
            "scopes": "openid profile offline_access",
            "allowed_audiences": [],
            "allowed_groups": [],
            "allowed_users": [],
            "generate_secret": "on",
        }

        confidential_response = self.client.post(
            "/console/clients/new/",
            {
                **common,
                "name": "Backend",
                "client_id": "console-backend",
                "application_type": OIDCClient.ApplicationType.WEB,
                "client_type": OIDCClient.ClientType.CONFIDENTIAL,
                "token_endpoint_auth_method": OIDCClient.AuthMethod.BASIC,
            },
        )
        self.assertEqual(confidential_response.status_code, 302, confidential_response.content)
        confidential = OIDCClient.objects.get(client_id="console-backend")
        raw_secret = self.client.session["new_client_secret"]
        self.assertEqual(confidential.secrets.count(), 1)
        self.assertTrue(confidential.check_secret(raw_secret))

        public_response = self.client.post(
            "/console/clients/new/",
            {
                **common,
                "name": "SPA",
                "client_id": "console-spa",
                "application_type": OIDCClient.ApplicationType.SPA,
                "client_type": OIDCClient.ClientType.PUBLIC,
                "token_endpoint_auth_method": OIDCClient.AuthMethod.POST,
                "client_credentials_enabled": "on",
            },
        )
        self.assertEqual(public_response.status_code, 302, public_response.content)
        public = OIDCClient.objects.get(client_id="console-spa")
        self.assertEqual(public.token_endpoint_auth_method, OIDCClient.AuthMethod.NONE)
        self.assertTrue(public.require_pkce)
        self.assertFalse(public.client_credentials_enabled)
        self.assertFalse(public.secrets.exists())


class JWTAndDiscoveryTests(OIDCTestCase):
    def test_jwt_is_rs256_signed_and_verifiable_from_public_jwks(self):
        user = User.objects.create_user(
            "alice",
            password="Alice-password-1",
            email="alice@example.com",
            first_name="Alice",
        )
        client = self.make_client("signed-app")
        tokens = issue_tokens(
            user, client, "openid profile email", nonce="nonce-123", include_refresh=False
        )
        access_header = jwt.get_unverified_header(tokens["access_token"])
        self.assertEqual(access_header["alg"], "RS256")

        discovery = self.client.get("/oidc/.well-known/openid-configuration").json()
        self.assertEqual(discovery["issuer"], ISSUER)
        self.assertIn("client_credentials", discovery["grant_types_supported"])
        jwks = self.client.get("/oidc/jwks/").json()["keys"]
        public_jwk = next(key for key in jwks if key["kid"] == access_header["kid"])
        self.assertEqual(public_jwk["use"], "sig")
        self.assertFalse({"d", "p", "q", "dp", "dq", "qi"} & set(public_jwk))

        claims = jwt.decode(
            tokens["access_token"],
            jwt.PyJWK(public_jwk).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=client.client_id,
        )
        self.assertEqual(claims["sub"], str(user.pk))
        self.assertEqual(claims["azp"], client.client_id)
        self.assertEqual(claims["token_use"], "access")
        self.assertTrue(claims["jti"])
        self.assertGreater(claims["exp"], claims["iat"])

        id_header = jwt.get_unverified_header(tokens["id_token"])
        id_jwk = next(key for key in jwks if key["kid"] == id_header["kid"])
        id_claims = jwt.decode(
            tokens["id_token"],
            jwt.PyJWK(id_jwk).key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=client.client_id,
        )
        self.assertEqual(id_claims["nonce"], "nonce-123")
        self.assertEqual(id_claims["preferred_username"], "alice")
        self.assertEqual(id_claims["email"], "alice@example.com")
        self.assertEqual(id_claims["token_use"], "id")
        self.assertTrue(SigningKey.objects.get(kid=access_header["kid"]).encrypted_private_key)

    def test_tampered_token_is_rejected_and_configured_ttls_are_applied(self):
        user = User.objects.create_user("alice")
        client = self.make_client("ttl-app")
        policy = SecurityPolicy.load()
        policy.access_token_ttl = 90
        policy.id_token_ttl = 120
        policy.save()
        tokens = issue_tokens(user, client, "openid", include_refresh=False)
        access = self.decode_without_verification(tokens["access_token"])
        identity = self.decode_without_verification(tokens["id_token"])
        self.assertEqual(tokens["expires_in"], 90)
        self.assertEqual(access["exp"] - access["iat"], 90)
        self.assertEqual(identity["exp"] - identity["iat"], 120)

        header, payload, signature = tokens["access_token"].split(".")
        first = "A" if signature[0] != "A" else "B"
        tampered = f"{header}.{payload}.{first}{signature[1:]}"
        response = self.client.get(
            "/oidc/userinfo/", HTTP_AUTHORIZATION=f"Bearer {tampered}"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "invalid_token")


class CompositeRolesAndSecretsTests(OIDCTestCase):
    def test_default_direct_and_composite_roles_expand_for_the_same_client(self):
        client=self.make_client("composite-api",access_policy=OIDCClient.AccessPolicy.RESTRICTED)
        user=User.objects.create_user("composite-user")
        default=ClientRole.objects.create(client=client,name="baseline",is_default=True)
        child=ClientRole.objects.create(client=client,name="read")
        parent=ClientRole.objects.create(client=client,name="operator")
        self.assertFalse(client.user_has_access(user),"Role padrão não deve contornar a política restrita")
        parent.composites.add(child); parent.users.add(user)
        self.assertTrue(client.user_has_access(user))
        self.assertEqual(client.effective_role_names(user),["baseline","operator","read"])

    def test_secret_rotation_keeps_a_short_overlap_without_storing_plaintext(self):
        client=self.make_client("secret-client",secret="first-secret")
        policy=SecurityPolicy.load(); policy.client_secret_grace_period=60; policy.save()
        client.set_secret("second-secret")
        self.assertTrue(client.check_secret("first-secret")); self.assertTrue(client.check_secret("second-secret"))
        self.assertFalse(client.secrets.filter(secret_hash__in=("first-secret","second-secret")).exists())
        client.secrets.exclude(expires_at__isnull=True).update(expires_at=timezone.now()-timezone.timedelta(seconds=1))
        self.assertFalse(client.check_secret("first-secret")); self.assertTrue(client.check_secret("second-secret"))


class AccountTests(TestCase):
    def test_new_user_receives_only_basic_self_service_access_automatically(self):
        user = User.objects.create_user("basic", password="Old-password-1")
        self.assertTrue(user.has_perm("identity.view_own_profile"))
        self.assertTrue(user.has_perm("identity.change_own_password"))
        self.assertFalse(user.has_perm("identity.view_identity_console"))
        self.client.force_login(user)
        response = self.client.post(
            "/account/password/",
            {
                "old_password": "Old-password-1",
                "new_password1": "New-strong-password-2",
                "new_password2": "New-strong-password-2",
            },
        )
        self.assertRedirects(response, "/account/")
        user.refresh_from_db()
        self.assertTrue(user.check_password("New-strong-password-2"))


class MFATestMixin:
    """Deterministic MFA fixtures shared by service and HTTP-level tests."""

    password = "Alice-password-1"
    # RFC 6238 SHA-1 test secret (the implementation intentionally emits 6 digits).
    totp_secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    fixed_time = 1_700_000_010

    def make_user(self, username="alice", **kwargs):
        return User.objects.create_user(
            username,
            email=f"{username}@example.com",
            password=self.password,
            **kwargs,
        )

    def enable_mfa_fixture(
        self,
        user,
        *,
        last_used_counter=-1,
        recovery_codes=(),
    ):
        mfa = UserMFA(
            user=user,
            encrypted_secret=b"",
            enabled=True,
            verified_at=timezone.now(),
            last_used_counter=last_used_counter,
            recovery_code_hashes=hash_recovery_codes(recovery_codes),
        )
        mfa.set_secret(self.totp_secret)
        mfa.save()
        return mfa

    def current_code(self, at_time=None):
        at_time = self.fixed_time if at_time is None else at_time
        return totp_code(self.totp_secret, int(at_time // 30))

    def begin_password_login(self, user, next_url="/account/"):
        response = self.client.post(
            "/login/",
            {
                "username": user.username,
                "password": self.password,
                "next": next_url,
            },
        )
        self.assertRedirects(response, "/login/2fa/", fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)
        challenge = MFAChallenge.objects.get(
            pk=self.client.session["mfa_challenge_id"]
        )
        self.assertEqual(challenge.user, user)
        self.assertEqual(challenge.next_url, next_url)
        self.assertIsNone(challenge.consumed_at)
        self.last_challenge = challenge
        return response


class MFAAlgorithmTests(MFATestMixin, TestCase):
    def test_totp_matches_rfc_6238_sha1_vectors_truncated_to_six_digits(self):
        vectors = {
            59: "287082",
            1_111_111_109: "081804",
            1_111_111_111: "050471",
            1_234_567_890: "005924",
            2_000_000_000: "279037",
            20_000_000_000: "353130",
        }
        for timestamp, expected in vectors.items():
            with self.subTest(timestamp=timestamp):
                counter = timestamp // 30
                self.assertEqual(totp_code(self.totp_secret, counter), expected)
                self.assertEqual(
                    matching_counter(
                        self.totp_secret,
                        expected,
                        at_time=timestamp,
                        window=0,
                    ),
                    counter,
                )

    def test_matching_counter_normalizes_display_format_and_honors_window(self):
        code = totp_code(self.totp_secret, 1)
        self.assertEqual(
            matching_counter(
                self.totp_secret,
                f"{code[:3]}-{code[3:]}",
                at_time=59,
                window=0,
            ),
            1,
        )
        self.assertIsNone(
            matching_counter(self.totp_secret, code, at_time=89, window=0)
        )
        self.assertEqual(
            matching_counter(self.totp_secret, code, at_time=89, window=1), 1
        )
        self.assertIsNone(
            matching_counter(self.totp_secret, "not-a-code", at_time=59)
        )

    def test_provisioning_uri_contains_standard_totp_parameters(self):
        user = self.make_user("totp-user")
        uri = provisioning_uri(user, self.totp_secret)
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "otpauth")
        self.assertEqual(parsed.netloc, "totp")
        self.assertIn("GateLite:totp-user@example.com", unquote(parsed.path))
        self.assertEqual(params["secret"], [self.totp_secret])
        self.assertEqual(params["issuer"], ["GateLite"])
        self.assertEqual(params["algorithm"], ["SHA1"])
        self.assertEqual(params["digits"], ["6"])
        self.assertEqual(params["period"], ["30"])


class MFASetupTests(MFATestMixin, TestCase):
    def setUp(self):
        self.user = self.make_user()
        self.client.force_login(self.user)

    def test_setup_reuses_encrypted_pending_secret_renders_qr_and_enables_mfa(self):
        response = self.client.get("/account/2fa/setup/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "account/mfa_setup.html")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        secret = response.context["secret"]
        self.assertEqual(len(secret), 32)
        self.assertEqual(response.context["provisioning_uri"], provisioning_uri(self.user, secret))

        qr_uri = response.context["qr_data_uri"]
        self.assertTrue(qr_uri.startswith("data:image/svg+xml;base64,"))
        qr_bytes = base64.b64decode(qr_uri.split(",", 1)[1])
        self.assertIn(b"<svg", qr_bytes)

        pending_ciphertext = base64.b64decode(
            self.client.session["mfa_setup_secret"]
        )
        self.assertNotIn(secret.encode(), pending_ciphertext)
        self.assertEqual(
            decrypt_value(pending_ciphertext, "pending-totp").decode(), secret
        )

        # Refreshing the setup page must not silently replace the authenticator secret.
        refreshed = self.client.get("/account/2fa/setup/")
        self.assertEqual(refreshed.context["secret"], secret)

        counter = self.fixed_time // 30
        valid_code = totp_code(secret, counter)
        invalid_code = "000000" if valid_code != "000000" else "999999"
        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            invalid = self.client.post(
                "/account/2fa/setup/", {"code": invalid_code}
            )
        self.assertEqual(invalid.status_code, 200)
        self.assertFormError(
            invalid.context["form"],
            "code",
            "Código inválido. Confira o horário do dispositivo e tente novamente.",
        )
        self.assertFalse(UserMFA.objects.filter(user=self.user).exists())

        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            enabled = self.client.post(
                "/account/2fa/setup/", {"code": valid_code}
            )
        self.assertEqual(enabled.status_code, 200)
        self.assertTemplateUsed(enabled, "account/mfa_recovery.html")
        recovery_codes = enabled.context["recovery_codes"]
        self.assertEqual(len(recovery_codes), 10)
        self.assertEqual(len(set(recovery_codes)), 10)
        self.assertEqual(enabled["Cache-Control"], "no-store")
        self.assertEqual(enabled["Referrer-Policy"], "no-referrer")

        mfa = UserMFA.objects.get(user=self.user)
        encrypted_secret = bytes(mfa.encrypted_secret)
        self.assertTrue(mfa.enabled)
        self.assertIsNotNone(mfa.verified_at)
        self.assertEqual(mfa.last_used_counter, counter)
        self.assertEqual(mfa.get_secret(), secret)
        self.assertTrue(UserSecurityState.objects.filter(user=self.user).exists())
        self.assertNotEqual(encrypted_secret, secret.encode())
        self.assertNotIn(secret.encode(), encrypted_secret)
        self.assertNotIn("mfa_setup_secret", self.client.session)
        self.assertEqual(
            self.client.session["mfa_verified_user_id"], self.user.pk
        )
        self.assertEqual(len(mfa.recovery_code_hashes), 10)
        for raw, hashed in zip(recovery_codes, mfa.recovery_code_hashes):
            self.assertNotEqual(raw, hashed)
            self.assertEqual(len(raw.replace("-", "")), 20)
            self.assertTrue(check_password(raw.replace("-", "").upper(), hashed))
        self.assertTrue(
            AuditEvent.objects.filter(
                actor=self.user,
                action="mfa.enabled",
                target_type="User",
                target_id=str(self.user.pk),
            ).exists()
        )
        serialized_audit = repr(
            list(
                AuditEvent.objects.filter(actor=self.user).values(
                    "action", "metadata"
                )
            )
        )
        self.assertNotIn(secret, serialized_audit)
        for raw in recovery_codes:
            self.assertNotIn(raw, serialized_audit)

        # The setup confirmation consumes its counter, preventing immediate reuse.
        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            self.assertFalse(verify_mfa(self.user, valid_code))

    def test_enabled_user_cannot_start_a_second_setup(self):
        self.enable_mfa_fixture(self.user)
        response = self.client.get("/account/2fa/setup/")
        self.assertRedirects(response, "/account/2fa/", fetch_redirect_response=False)


class MFALoginTests(MFATestMixin, TestCase):
    def setUp(self):
        self.user = self.make_user()
        self.mfa = self.enable_mfa_fixture(self.user)

    def test_password_and_totp_are_two_distinct_steps_and_totp_cannot_replay(self):
        self.begin_password_login(self.user)
        code = self.current_code()
        invalid_code = "000000" if code != "000000" else "999999"

        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            invalid = self.client.post("/login/2fa/", {"code": invalid_code})
        self.assertEqual(invalid.status_code, 200)
        self.assertFormError(
            invalid.context["form"],
            "code",
            "Código inválido, expirado ou já utilizado. Restam 4 tentativas.",
        )
        self.assertNotIn("_auth_user_id", self.client.session)
        self.last_challenge.refresh_from_db()
        self.assertEqual(self.last_challenge.attempts, 1)

        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            verified = self.client.post("/login/2fa/", {"code": code})
        self.assertRedirects(verified, "/account/", fetch_redirect_response=False)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)
        self.assertEqual(
            self.client.session["mfa_verified_user_id"], self.user.pk
        )
        self.assertNotIn("mfa_challenge_id", self.client.session)
        self.last_challenge.refresh_from_db()
        self.assertIsNotNone(self.last_challenge.consumed_at)
        self.assertEqual(
            self.client.session["authentication_methods"], ["pwd", "otp"]
        )
        self.assertEqual(
            self.client.session["authentication_acr"], "urn:gatelite:acr:2"
        )
        self.mfa.refresh_from_db()
        self.assertEqual(self.mfa.last_used_counter, self.fixed_time // 30)

        self.client.logout()
        self.begin_password_login(self.user)
        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            replay = self.client.post("/login/2fa/", {"code": code})
        self.assertEqual(replay.status_code, 200)
        self.assertFormError(
            replay.context["form"],
            "code",
            "Código inválido, expirado ou já utilizado. Restam 4 tentativas.",
        )
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_recovery_code_is_case_and_separator_tolerant_but_single_use(self):
        recovery_code = "ABCD-EFGH-JKLM"
        self.mfa.recovery_code_hashes = hash_recovery_codes([recovery_code])
        self.mfa.save(update_fields=["recovery_code_hashes", "updated_at"])
        self.begin_password_login(self.user)

        verified = self.client.post(
            "/login/2fa/", {"code": recovery_code.lower().replace("-", " ")}
        )
        self.assertRedirects(verified, "/account/", fetch_redirect_response=False)
        self.mfa.refresh_from_db()
        self.assertEqual(self.mfa.recovery_code_hashes, [])
        self.assertEqual(
            self.client.session["authentication_methods"], ["pwd", "recovery"]
        )

        self.client.logout()
        self.begin_password_login(self.user)
        replay = self.client.post("/login/2fa/", {"code": recovery_code})
        self.assertEqual(replay.status_code, 200)
        self.assertFormError(
            replay.context["form"],
            "code",
            "Código inválido, expirado ou já utilizado. Restam 4 tentativas.",
        )
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_pending_login_expires_and_is_removed_from_the_session(self):
        self.begin_password_login(self.user, next_url="/console/clients/")
        self.last_challenge.expires_at = timezone.now() - timezone.timedelta(
            seconds=1
        )
        self.last_challenge.save(update_fields=["expires_at"])

        expired = self.client.get("/login/2fa/")
        self.assertRedirects(expired, "/login/", fetch_redirect_response=False)
        self.assertNotIn("mfa_challenge_id", self.client.session)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_five_invalid_attempts_consume_challenge_and_lock_the_user(self):
        self.begin_password_login(self.user)
        for attempt in range(1, 6):
            response = self.client.post("/login/2fa/", {"code": "invalid"})
            if attempt < 5:
                self.assertEqual(response.status_code, 200)
                self.assertFormError(
                    response.context["form"],
                    "code",
                    f"Código inválido, expirado ou já utilizado. Restam {5-attempt} tentativas.",
                )
            else:
                self.assertRedirects(
                    response, "/login/", fetch_redirect_response=False
                )

        self.last_challenge.refresh_from_db()
        self.mfa.refresh_from_db()
        self.assertEqual(self.last_challenge.attempts, 5)
        self.assertIsNotNone(self.last_challenge.consumed_at)
        self.assertIsNotNone(self.mfa.locked_until)
        self.assertGreater(self.mfa.locked_until, timezone.now())
        self.assertNotIn("mfa_challenge_id", self.client.session)

        # Repeating the password step must not create a fresh challenge that
        # bypasses the per-user lock.
        locked = self.client.post(
            "/login/",
            {"username": self.user.username, "password": self.password},
        )
        self.assertEqual(locked.status_code, 429)
        self.assertFormError(
            locked.context["form"],
            None,
            "Segundo fator temporariamente bloqueado. Tente novamente mais tarde.",
        )
        self.assertContains(
            locked,
            "Segundo fator temporariamente bloqueado. Tente novamente mais tarde.",
            status_code=429,
        )
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(MFAChallenge.objects.filter(user=self.user).count(), 1)

    def test_challenge_is_invalidated_when_password_changes(self):
        self.begin_password_login(self.user)
        self.user.set_password("Different-password-2")
        self.user.save(update_fields=["password"])

        invalidated = self.client.get("/login/2fa/")
        self.assertRedirects(
            invalidated, "/login/", fetch_redirect_response=False
        )
        self.assertNotIn("mfa_challenge_id", self.client.session)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_external_next_url_is_replaced_with_local_account_page(self):
        response = self.client.post(
            "/login/",
            {
                "username": self.user.username,
                "password": self.password,
                "next": "https://evil.example/steal",
            },
        )
        self.assertRedirects(response, "/login/2fa/", fetch_redirect_response=False)
        challenge = MFAChallenge.objects.get(
            pk=self.client.session["mfa_challenge_id"]
        )
        self.assertEqual(challenge.next_url, "/account/")


class MFARecoveryAndDisableTests(MFATestMixin, TestCase):
    def setUp(self):
        self.user = self.make_user()
        self.old_recovery_code = "ABCD-EFGH-JKLM"
        self.mfa = self.enable_mfa_fixture(
            self.user, recovery_codes=[self.old_recovery_code]
        )
        self.security_state = UserSecurityState.objects.get(user=self.user)
        self.original_authentication_version = self.security_state.authentication_version
        self.client.force_login(self.user)
        session = self.client.session
        session["mfa_verified_user_id"] = self.user.pk
        session.save()

    def test_recovery_codes_can_be_regenerated_only_with_password_and_mfa(self):
        code = self.current_code()
        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            response = self.client.post(
                "/account/2fa/recovery/",
                {"password": self.password, "code": code},
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "account/mfa_recovery.html")
        new_codes = response.context["recovery_codes"]
        self.assertEqual(len(new_codes), 10)
        self.assertNotIn(self.old_recovery_code, new_codes)

        self.mfa.refresh_from_db()
        self.assertEqual(len(self.mfa.recovery_code_hashes), 10)
        self.assertFalse(
            any(
                check_password(
                    self.old_recovery_code.replace("-", "").upper(), hashed
                )
                for hashed in self.mfa.recovery_code_hashes
            )
        )
        for raw, hashed in zip(new_codes, self.mfa.recovery_code_hashes):
            self.assertTrue(check_password(raw.replace("-", "").upper(), hashed))
        self.assertTrue(
            AuditEvent.objects.filter(
                actor=self.user,
                action="mfa.recovery_codes_regenerated",
                target_id=str(self.user.pk),
            ).exists()
        )

    def test_disable_rejects_wrong_password_without_consuming_totp_then_removes_mfa(self):
        code = self.current_code()
        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            denied = self.client.post(
                "/account/2fa/disable/",
                {"password": "wrong-password", "code": code},
            )
        self.assertEqual(denied.status_code, 400)
        self.assertFormError(denied.context["disable_form"], "password", "Senha incorreta.")
        self.mfa.refresh_from_db()
        self.assertEqual(self.mfa.last_used_counter, -1)

        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            disabled = self.client.post(
                "/account/2fa/disable/",
                {"password": self.password, "code": code},
            )
        self.assertRedirects(
            disabled, "/account/2fa/", fetch_redirect_response=False
        )
        self.assertFalse(UserMFA.objects.filter(user=self.user).exists())
        self.assertNotIn("mfa_verified_user_id", self.client.session)
        self.security_state.refresh_from_db()
        self.assertNotEqual(
            self.security_state.authentication_version,
            self.original_authentication_version,
        )
        self.assertTrue(
            AuditEvent.objects.filter(
                actor=self.user,
                action="mfa.disabled",
                target_id=str(self.user.pk),
            ).exists()
        )


class MFAOIDCTests(MFATestMixin, OIDCTestCase):
    def setUp(self):
        self.user = self.make_user()
        self.enable_mfa_fixture(self.user)

    def test_mfa_assurance_is_persisted_in_oidc_session_and_signed_tokens(self):
        oidc_client = self.make_client(
            "mfa-spa",
            client_type=OIDCClient.ClientType.PUBLIC,
            require_mfa=True,
        )
        self.begin_password_login(self.user)
        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            login_response = self.client.post(
                "/login/2fa/", {"code": self.current_code()}
            )
        self.assertRedirects(
            login_response, "/account/", fetch_redirect_response=False
        )

        verifier, code_challenge = self.pkce()
        authorize_response = self.client.get(
            "/oidc/authorize/",
            {
                "client_id": oidc_client.client_id,
                "redirect_uri": oidc_client.uri_list()[0],
                "response_type": "code",
                "scope": "openid profile",
                "state": "mfa-state",
                "nonce": "mfa-nonce",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        query = parse_qs(urlparse(authorize_response.url).query)
        self.assertIn("code", query, query)
        oidc_session = OIDCSession.objects.get(user=self.user, client=oidc_client)
        self.assertEqual(oidc_session.authentication_methods, ["pwd", "otp"])
        self.assertEqual(oidc_session.acr, "urn:gatelite:acr:2")
        self.assertEqual(
            int(oidc_session.auth_time.timestamp()),
            self.client.session["authentication_time"],
        )

        token_response = self.exchange_code(
            oidc_client,
            query["code"][0],
            oidc_client.uri_list()[0],
            verifier=verifier,
        )
        self.assertEqual(token_response.status_code, 200, token_response.content)
        for token_name in ("access_token", "id_token"):
            with self.subTest(token_name=token_name):
                claims = self.decode_without_verification(
                    token_response.json()[token_name]
                )
                self.assertEqual(claims["amr"], ["pwd", "otp"])
                self.assertEqual(claims["acr"], "urn:gatelite:acr:2")
                self.assertEqual(
                    claims["auth_time"], int(oidc_session.auth_time.timestamp())
                )

        discovery = self.client.get(
            "/oidc/.well-known/openid-configuration"
        ).json()
        self.assertIn("amr", discovery["claims_supported"])
        self.assertIn("acr", discovery["claims_supported"])
        self.assertIn("auth_time", discovery["claims_supported"])
        self.assertIn("urn:gatelite:acr:2", discovery["acr_values_supported"])

    def test_mfa_client_steps_up_an_authenticated_but_unverified_session(self):
        oidc_client = self.make_client(
            "step-up-spa",
            client_type=OIDCClient.ClientType.PUBLIC,
            require_mfa=True,
        )
        self.client.force_login(self.user)
        _, code_challenge = self.pkce()
        response = self.client.get(
            "/oidc/authorize/",
            {
                "client_id": oidc_client.client_id,
                "redirect_uri": oidc_client.uri_list()[0],
                "response_type": "code",
                "scope": "openid",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertRedirects(response, "/login/2fa/", fetch_redirect_response=False)
        challenge = MFAChallenge.objects.get(
            pk=self.client.session["mfa_challenge_id"]
        )
        self.assertEqual(challenge.user, self.user)
        self.assertTrue(challenge.next_url.startswith("/oidc/authorize/"))
        self.assertFalse(OIDCSession.objects.filter(user=self.user).exists())


class MFAEnforcementAndAdminResetTests(MFATestMixin, TestCase):
    def test_django_admin_login_uses_the_same_two_factor_flow(self):
        admin = self.make_user("django-admin", is_staff=True, is_superuser=True)
        self.enable_mfa_fixture(admin)

        entry = self.client.get("/admin/login/?next=/admin/")
        self.assertRedirects(
            entry,
            "/login/?next=%2Fadmin%2F",
            fetch_redirect_response=False,
        )
        password_step = self.client.post(
            "/login/",
            {
                "username": admin.username,
                "password": self.password,
                "next": "/admin/",
            },
        )
        self.assertRedirects(
            password_step, "/login/2fa/", fetch_redirect_response=False
        )
        self.assertNotIn("_auth_user_id", self.client.session)

        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            verified = self.client.post(
                "/login/2fa/", {"code": self.current_code()}
            )
        self.assertRedirects(verified, "/admin/", fetch_redirect_response=False)
        self.assertEqual(int(self.client.session["_auth_user_id"]), admin.pk)

    def test_admin_policy_requires_setup_then_challenges_an_enabled_admin(self):
        policy = SecurityPolicy.load()
        policy.mfa_mode = SecurityPolicy.MFAMode.ADMINS
        policy.save()
        admin = self.make_user("root", is_staff=True, is_superuser=True)
        self.client.force_login(admin)

        setup_required = self.client.get("/")
        self.assertEqual(setup_required.status_code, 302)
        setup_url = urlparse(setup_required.url)
        self.assertEqual(setup_url.path, "/account/2fa/setup/")
        self.assertEqual(parse_qs(setup_url.query), {"next": ["/"]})

        self.enable_mfa_fixture(admin)
        challenged = self.client.get("/console/settings/")
        self.assertRedirects(
            challenged, "/login/2fa/", fetch_redirect_response=False
        )
        challenge = MFAChallenge.objects.get(
            pk=self.client.session["mfa_challenge_id"]
        )
        self.assertEqual(challenge.user, admin)
        self.assertEqual(
            challenge.next_url, "/console/settings/"
        )

        with patch("identity.mfa.time.time", return_value=self.fixed_time):
            verified = self.client.post(
                "/login/2fa/", {"code": self.current_code()}
            )
        self.assertRedirects(
            verified, "/console/settings/", fetch_redirect_response=False
        )
        allowed = self.client.get("/console/settings/")
        self.assertEqual(allowed.status_code, 200)

    def test_admin_policy_includes_console_permission_inherited_from_group(self):
        policy = SecurityPolicy.load()
        policy.mfa_mode = SecurityPolicy.MFAMode.ADMINS
        policy.save()
        operator = self.make_user("group-operator")
        operators = Group.objects.create(name="identity-operators")
        operators.permissions.add(
            Permission.objects.get(
                content_type__app_label="identity",
                codename="view_identity_console",
            )
        )
        operator.groups.add(operators)
        self.client.force_login(operator)

        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response.url)
        self.assertEqual(parsed.path, "/account/2fa/setup/")
        self.assertEqual(parse_qs(parsed.query), {"next": ["/"]})

    def test_console_user_edit_can_reset_another_users_mfa(self):
        admin = self.make_user("mfa-admin", is_staff=True, is_superuser=True)
        target = self.make_user("target")
        self.enable_mfa_fixture(target, recovery_codes=["ABCD-EFGH-JKLM"])
        security_state = UserSecurityState.objects.get(user=target)
        original_authentication_version = security_state.authentication_version
        self.client.force_login(admin)

        response = self.client.post(
            f"/console/users/{target.pk}/",
            {
                "username": target.username,
                "first_name": target.first_name,
                "last_name": target.last_name,
                "email": target.email,
                "new_password": "",
                "groups": [],
                "client_roles": [],
                "is_active": "on",
                "user_permissions": [],
                "reset_mfa": "on",
            },
        )
        self.assertRedirects(
            response, "/console/users/", fetch_redirect_response=False
        )
        self.assertFalse(UserMFA.objects.filter(user=target).exists())
        security_state.refresh_from_db()
        self.assertNotEqual(
            security_state.authentication_version, original_authentication_version
        )
        self.assertTrue(
            AuditEvent.objects.filter(
                actor=admin,
                action="users.updated",
                target_type="User",
                target_id=str(target.pk),
            ).exists()
        )


class EndSessionTests(OIDCTestCase):
    def setUp(self):
        self.user = User.objects.create_user("logout-user", password="Strong-password-123!")
        self.web = self.make_client("portal-logout")
        ClientURI.objects.create(
            client=self.web,
            kind=ClientURI.Kind.POST_LOGOUT,
            uri="https://portal-logout.example/signed-out",
        )

    def test_end_session_revokes_sid_ends_the_browser_session_and_echoes_state(self):
        tokens = self.tokens_via_code(self.web, self.user, scope="openid")
        sid = self.decode_without_verification(tokens["id_token"])["sid"]

        response = self.client.get("/oidc/logout/", {
            "id_token_hint": tokens["id_token"],
            "post_logout_redirect_uri": "https://portal-logout.example/signed-out",
            "state": "after-logout",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://portal-logout.example/signed-out?state=after-logout")
        self.assertIsNotNone(OIDCSession.objects.get(pk=sid).revoked_at)

        protected = self.client.get("/account/")
        self.assertEqual(protected.status_code, 302)
        self.assertIn("/login/", protected.url)

    def test_unregistered_uri_or_missing_hint_never_produces_an_open_redirect(self):
        tokens = self.tokens_via_code(self.web, self.user, scope="openid")

        hijack = self.client.get("/oidc/logout/", {
            "id_token_hint": tokens["id_token"],
            "post_logout_redirect_uri": "https://evil.example/phish",
        })
        self.assertEqual(hijack.status_code, 302)
        self.assertEqual(hijack.url, "/login/")

        self.client.force_login(self.user)
        hintless = self.client.get("/oidc/logout/", {
            "post_logout_redirect_uri": "https://portal-logout.example/signed-out",
        })
        self.assertEqual(hintless.status_code, 302)
        self.assertEqual(hintless.url, "/login/")

        self.client.force_login(self.user)
        tampered = tokens["id_token"][:-6] + "aaaaaa"
        forged_hint = self.client.get("/oidc/logout/", {
            "id_token_hint": tampered,
            "post_logout_redirect_uri": "https://portal-logout.example/signed-out",
        })
        self.assertEqual(forged_hint.status_code, 302)
        self.assertEqual(forged_hint.url, "/login/")


class RetiredSigningKeyTests(OIDCTestCase):
    def test_tokens_from_a_long_retired_key_are_rejected_like_the_jwks(self):
        user = User.objects.create_user("key-user", password="Strong-password-123!")
        client = self.make_client("portal-keys")
        tokens = self.tokens_via_code(client, user, scope="openid")
        old = SigningKey.objects.get(active=True)

        # Dentro da janela de retenção a chave recém-aposentada continua válida,
        # exatamente como no JWKS publicado.
        old.active = False
        old.retired_at = timezone.now()
        old.save(update_fields=["active", "retired_at"])
        within = self.client.get(
            "/oidc/userinfo/", HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}"
        )
        self.assertEqual(within.status_code, 200)

        # Além da retenção, nem um token forjado com exp futuro pela chave
        # antiga (cenário de chave comprometida e rotacionada) é aceito.
        policy = SecurityPolicy.load()
        retention = max(policy.access_token_ttl, policy.id_token_ttl) + 300
        old.retired_at = timezone.now() - timezone.timedelta(seconds=retention + 60)
        old.save(update_fields=["retired_at"])
        import time as time_module
        now = int(time_module.time())
        forged = jwt.encode(
            {
                "iss": ISSUER, "sub": str(user.pk), "aud": client.client_id,
                "azp": client.client_id, "jti": "forged-jti", "iat": now,
                "exp": now + 3600, "scope": "openid", "token_use": "access",
            },
            private_pem(old), algorithm="RS256", headers={"kid": old.kid},
        )
        rejected = self.client.get("/oidc/userinfo/", HTTP_AUTHORIZATION=f"Bearer {forged}")
        self.assertEqual(rejected.status_code, 401)


class LoginLockoutTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("lockout-user", password="Strong-password-123!")
        policy = SecurityPolicy.load()
        policy.login_max_attempts = 3
        policy.login_lockout_seconds = 300
        policy.save()

    def attempt(self, password):
        return self.client.post("/login/", {"username": "lockout-user", "password": password})

    def test_configured_attempts_lock_the_account_and_expiry_unlocks(self):
        from django.contrib.auth import SESSION_KEY

        for _ in range(3):
            self.assertEqual(self.attempt("wrong-password").status_code, 200)
        state = UserSecurityState.objects.get(user=self.user)
        self.assertIsNotNone(state.login_locked_until)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="authentication.locked_out", target_id=str(self.user.pk)
            ).exists()
        )

        locked = self.attempt("Strong-password-123!")
        self.assertEqual(locked.status_code, 429)
        self.assertContains(locked, "bloqueada", status_code=429)
        self.assertNotIn(SESSION_KEY, self.client.session)

        UserSecurityState.objects.filter(user=self.user).update(
            login_locked_until=timezone.now() - timezone.timedelta(seconds=1)
        )
        unlocked = self.attempt("Strong-password-123!")
        self.assertEqual(unlocked.status_code, 302)
        state.refresh_from_db()
        self.assertEqual(state.failed_login_attempts, 0)
        self.assertIsNone(state.login_locked_until)

    def test_successful_login_resets_the_failure_counter(self):
        self.attempt("wrong-password")
        self.attempt("wrong-password")
        self.assertEqual(self.attempt("Strong-password-123!").status_code, 302)
        state = UserSecurityState.objects.get(user=self.user)
        self.assertEqual(state.failed_login_attempts, 0)
        self.assertIsNone(state.login_locked_until)
