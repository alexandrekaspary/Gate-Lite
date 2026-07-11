from django.urls import path
from . import views
urlpatterns=[
 path(".well-known/openid-configuration",views.discovery,name="discovery"),path("jwks/",views.jwks,name="jwks"),
 path("authorize/",views.authorize,name="authorize"),path("token/",views.token,name="token"),path("userinfo/",views.userinfo,name="userinfo"),path("revoke/",views.revoke,name="revoke"),path("introspect/",views.introspect,name="introspect"),path("logout/",views.end_session,name="end_session")]
