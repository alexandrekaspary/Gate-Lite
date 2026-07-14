from django.shortcuts import render


def bad_request(request, exception=None):
    return render(request, "errors/400.html", status=400)


def permission_denied(request, exception=None):
    return render(request, "errors/403.html", status=403)


def csrf_failure(request, reason=""):
    # CSRF é rejeitado pelo middleware antes de chegar à view, então usa
    # CSRF_FAILURE_VIEW em vez de handler403 — por isso precisa de handler próprio.
    return render(request, "errors/403.html", status=403)


def page_not_found(request, exception=None):
    return render(request, "errors/404.html", status=404)


def server_error(request):
    return render(request, "errors/500.html", status=500)
