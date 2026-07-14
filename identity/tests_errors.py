from django.conf import settings
from django.test import Client, RequestFactory, SimpleTestCase, override_settings

from gatelite import errors, urls


class ErrorPageTests(SimpleTestCase):
    def setUp(self):
        self.request = RequestFactory().get("/missing/")

    def test_error_handlers_render_the_expected_status_and_message(self):
        cases = (
            (errors.bad_request(self.request), 400, "Não conseguimos entender este pedido"),
            (errors.permission_denied(self.request), 403, "Você não tem acesso"),
            (errors.csrf_failure(self.request), 403, "Você não tem acesso"),
            (errors.page_not_found(self.request), 404, "Não encontramos esta página"),
            (errors.server_error(self.request), 500, "Algo deu errado no servidor"),
        )
        for response, status, message in cases:
            with self.subTest(status=status):
                self.assertEqual(response.status_code, status)
                self.assertContains(response, message, status_code=status)

    def test_root_urlconf_registers_the_handlers(self):
        self.assertEqual(urls.handler400, "gatelite.errors.bad_request")
        self.assertEqual(urls.handler403, "gatelite.errors.permission_denied")
        self.assertEqual(urls.handler404, "gatelite.errors.page_not_found")
        self.assertEqual(urls.handler500, "gatelite.errors.server_error")

    def test_csrf_failure_view_is_registered(self):
        # CSRF é rejeitado pelo middleware antes da view, então usa
        # CSRF_FAILURE_VIEW em vez de handler403 — configuração própria e fácil de esquecer.
        self.assertEqual(settings.CSRF_FAILURE_VIEW, "gatelite.errors.csrf_failure")

    @override_settings(DEBUG=False)
    def test_unknown_route_uses_the_custom_404_page(self):
        response = self.client.get("/route-that-does-not-exist/")
        self.assertContains(response, "Não encontramos esta página", status_code=404)

    @override_settings(DEBUG=False, ALLOWED_HOSTS=["testserver"])
    def test_disallowed_host_uses_the_custom_400_page(self):
        response = self.client.get("/login/", HTTP_HOST="not-a-trusted-host.example")
        self.assertContains(response, "Não conseguimos entender este pedido", status_code=400)

    @override_settings(DEBUG=False)
    def test_a_real_csrf_rejection_uses_the_custom_403_page(self):
        enforcing_client = Client(enforce_csrf_checks=True)
        response = enforcing_client.post("/login/", {"username": "someone", "password": "x"})
        self.assertContains(response, "Você não tem acesso", status_code=403)
