"""
URL configuration for project_name project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static

from django.contrib import admin
from django.urls import path, include
from django.conf.urls.i18n import i18n_patterns
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from main.urls import apiurls as main_api_urls
from users.urls import api_urls as user_api_urls



api_urls = ([
    path('main/', include(main_api_urls, namespace='main')),
                path('users/', include(user_api_urls, namespace='account')),
            ], 'api')


urlpatterns = [
    path('documentation/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('documentation/api/',
         SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('admin/', admin.site.urls),
    path('', include('main.urls')),
    path('account/', include('users.urls')),
    path('api/', include(api_urls, namespace='api')),
    path("i18n/", include("django.conf.urls.i18n")),

]

urlpatterns += i18n_patterns(path("admin/", admin.site.urls))

if not settings.IS_PRODUCTION:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

