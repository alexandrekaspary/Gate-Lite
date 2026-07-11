from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from identity.views import SecurePasswordResetCompleteView, SecurePasswordResetConfirmView, VerifiedPasswordResetDoneView, VerifiedPasswordResetView, account, account_email_confirm, account_email_resend, account_mfa, account_mfa_disable, account_mfa_recovery, account_mfa_setup, account_profile_edit, admin_login_redirect, change_own_password, discovery, login_2fa, login_view, revoke_own_session

urlpatterns = [
    path(".well-known/openid-configuration", discovery, name="openid-configuration"),
    path("admin/login/", admin_login_redirect, name="admin-login-redirect"),
    path("admin/", admin.site.urls),
    path("login/", login_view, name="login"),
    path("login/2fa/", login_2fa, name="login-2fa"),
    path("password/reset/", VerifiedPasswordResetView.as_view(), name="password-reset"),
    path("password/reset/done/", VerifiedPasswordResetDoneView.as_view(), name="password-reset-done"),
    path("password/reset/<uidb64>/<token>/", SecurePasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("password/reset/complete/", SecurePasswordResetCompleteView.as_view(), name="password-reset-complete"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("account/", account, name="account"),
    path("account/profile/", account_profile_edit, name="account-profile-edit"),
    path("account/email/resend/", account_email_resend, name="account-email-resend"),
    path("account/email/confirm/", account_email_confirm, name="account-email-confirm"),
    path("account/password/", change_own_password, name="change-own-password"),
    path("account/2fa/", account_mfa, name="account-mfa"),
    path("account/2fa/setup/", account_mfa_setup, name="account-mfa-setup"),
    path("account/2fa/disable/", account_mfa_disable, name="account-mfa-disable"),
    path("account/2fa/recovery/", account_mfa_recovery, name="account-mfa-recovery"),
    path("account/sessions/<uuid:pk>/revoke/", revoke_own_session, name="revoke-own-session"),
    path("oidc/", include("identity.oidc_urls")),
    path("", include("identity.console_urls")),
]
