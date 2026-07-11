from django.test import RequestFactory, SimpleTestCase, override_settings

from gatelite import errors, urls


class ErrorPageTests(SimpleTestCase):
    def setUp(self):
        self.request = RequestFactory().get("/missing/")

    def test_error_handlers_render_the_expected_status_and_message(self):
        cases = (
            (errors.permission_denied(self.request), 403, "Você não tem acesso"),
            (errors.page_not_found(self.request), 404, "Não encontramos esta página"),
            (errors.server_error(self.request), 500, "Algo deu errado no servidor"),
        )
        for response, status, message in cases:
            with self.subTest(status=status):
                self.assertEqual(response.status_code, status)
                self.assertContains(response, message, status_code=status)

    def test_root_urlconf_registers_the_handlers(self):
        self.assertEqual(urls.handler403, "gatelite.errors.permission_denied")
        self.assertEqual(urls.handler404, "gatelite.errors.page_not_found")
        self.assertEqual(urls.handler500, "gatelite.errors.server_error")

    @override_settings(DEBUG=False)
    def test_unknown_route_uses_the_custom_404_page(self):
        response = self.client.get("/route-that-does-not-exist/")
        self.assertContains(response, "Não encontramos esta página", status_code=404)
