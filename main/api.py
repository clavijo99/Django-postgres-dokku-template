from drf_spectacular.utils import extend_schema
from main.models import Configuration
from main.serializers import ConfigurationSerializer
from rest_framework import viewsets, permissions



@extend_schema(tags=['Settings'])
class ConfigurationView(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.AllowAny]
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
