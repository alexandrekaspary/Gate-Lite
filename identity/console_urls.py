from django.urls import path
from . import views
app_name="console"
urlpatterns=[
 path("",views.dashboard,name="dashboard"),path("console/settings/",views.settings_panel,name="settings"),
 path("console/keys/",views.keys,name="keys"),path("console/keys/rotate/",views.rotate_key,name="rotate_key"),
 path("console/<str:kind>/",views.object_list,name="list"),path("console/<str:kind>/new/",views.object_form,name="create"),
 path("console/<str:kind>/<int:pk>/",views.object_form,name="edit"),path("console/<str:kind>/<int:pk>/delete/",views.object_delete,name="delete")]
