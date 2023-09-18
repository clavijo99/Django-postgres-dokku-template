# general imports
from django.urls import path, include
from main.views import home
from rest_framework import routers
from main.api import ConfigurationView

# api urls
api_router = routers.DefaultRouter()
# /api/main/configurations
api_router.register('configurations', ConfigurationView)

apiurls = ([
    # /api/main/<routers>
    path('', include(api_router.urls))
], 'main')

urlpatterns = [
    path('', home, name="home"),
]
