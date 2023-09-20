import logging
from django.utils.crypto import get_random_string
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from rest_framework import permissions, status, mixins, viewsets, parsers
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.utils.translation import gettext_lazy as _
from .models import User
from .serializers import CustomTokenObtainPairSerializer, UserModelSerializer, RegisterSerializer, TokenOutput, \
    LogoutSerializer, ResetPasswordSerializer, ResetPasswordRequestSerializer,  UserAvatarSerializer
from main.serializers import DefaultResponseSerializer

logger = logging.getLogger(__name__)


@extend_schema(tags=['Usuario'])
class UserDetailAPIView(GenericAPIView):
    """
    get:
    Get current account.
    This API resources use API View.
    post:
    Update current account.
    """

    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    @extend_schema(
        request=UserModelSerializer,
        summary=_(
            "Obtiene la información de un usuario mediante el nombre usuario"),
        description=_(
            "Obtiene la información de un usuario mediante el nombre usuario"),
        responses={
            200: UserModelSerializer,
            404: OpenApiResponse(description=_('El Usuario no existe')),
        },
        methods=["get"]
    )
    def get(self, request, username):
        user = get_object_or_404(User, username=username)
        serializer = UserModelSerializer(user)
        return Response(serializer.data)

    @extend_schema(
        request=UserModelSerializer,
        summary=_(
            "Actualiza los datos del usuario, solo el usuario puede actualizar sus datos"),
        description=_(
            "Actualiza los datos del usuario, solo el usuario puede actualizar sus datos"),
        responses={
            200: UserModelSerializer,
            404: OpenApiResponse(description=_('El Usuario no existe')),
            400: OpenApiResponse(description=_('Datos inválidos')),
            401: OpenApiResponse(description=_('Usted no tiene permiso para actualizar este usuario')),
        },
        methods=["post"]
    )
    def post(self, request, username):
        # Only can update yourself
        if request.user.username == username:
            user = get_object_or_404(User, username=username)
            serializer = UserModelSerializer(user, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'detail': _("Usted no tiene permiso para actualizar este usuario")},
                            status=status.HTTP_401_UNAUTHORIZED)

    @extend_schema(
        request=UserModelSerializer,
        summary=_(
            "Elimina un usuario, solo el usuario se puede eliminar a si mismo"),
        description=_(
            "Elimina un usuario, solo el usuario se puede eliminar a si mismo"),
        responses={
            201: OpenApiResponse(description=_('Eliminación exitosa del usuario')),
            404: OpenApiResponse(description=_('El Usuario no existe')),
            400: OpenApiResponse(description=_('Usted no tiene permiso para eliminar este usuario')),
        },
        methods=["delete"]
    )
    def delete(self, request, username):
        # Only can delete yourself
        if request.user.username == username:
            user = get_object_or_404(User, pk=request.user.id)
            user.status = "DELETED"
            user.is_active = False
            user.save()
            return Response({"status": "OK"})
        else:
            return Response({'detail': _('Usted no tiene permiso para eliminar este usuario')},
                            status.HTTP_400_BAD_REQUEST)

@extend_schema(tags=['Usuario'])
class AvatarViewSet(viewsets.GenericViewSet, mixins.DestroyModelMixin):
    permission_classes = [permissions.IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserAvatarSerializer
    parser_classes = (
        parsers.MultiPartParser,
        parsers.FormParser,
        parsers.JSONParser,
    )

    @extend_schema(
        summary=_("Anexar una imagen al avatar de usuario"),
        description=_("Anexar una imagen al avatar del usuario"),
        request={
            'multipart/form-data': {
                'type': 'object',
                'properties': {
                    'avatar': {
                        'type': 'string',
                        'format': 'binary'
                    },
                }
            }
        },
        # request=UserAvatarSerializer,
        responses={200: UserModelSerializer},
        methods=["post"]
    )
    @action(
        methods=['post'],
        detail=False,
    )
    def avatar(self, request):
        try:
            user = request.user
            serializer = self.get_serializer(data=request.data)  # noqa
            if serializer.is_valid(raise_exception=True):
                user.avatar = serializer.validated_data['avatar']
                user.save()

                user_serializer = UserModelSerializer(user)
                return Response(user_serializer.data, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get_success_headers(self, data):  # noqa
        try:
            return {'Location': str(data[api_settings.URL_FIELD_NAME])}
        except (TypeError, KeyError):
            return {}

@extend_schema(tags=['Usuario'])
class CurrentUserAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary=_("Obtiene el usuario actual atravez del token de la sesion"),
        description=_(
            "Obtiene el usuario actual atravez del token de la sesion"),
        responses={
            200: UserModelSerializer,
            401: OpenApiResponse(description=_('Usted no tiene permiso para ver este usuario')),
        },
        methods=["get"]
    )
    def get(self, request):
        """
        Authenticate current account and return his/her details
        """
        current_user = UserModelSerializer(request.user, )
        logger.info(f"Authenticating current account {request.user.username}")

        return Response(current_user.data)


@extend_schema(tags=['Autenticacion'])
class RegisterAPIView(GenericAPIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary=_("Registrar un nuevo usuario"),
        description=_("Registrar un nuevo usuario"),
        request=RegisterSerializer,
        responses={200: UserModelSerializer},
        methods=["post"]
    )
    def post(self, request, *args, **kwargs):
        try:
            """
            Register a new account and return it's details
            """
            serializer = RegisterSerializer(data=request.data)
            print('create')
            if serializer.is_valid():
                user = serializer.save()
                print('serializers')
                return Response(UserModelSerializer(user).data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            exception_message = str(e)
            print(e)
            return Response({'detail': exception_message}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(tags=['Autenticacion'])
class ResetPasswordRequestAPIView(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ResetPasswordRequestSerializer

    @extend_schema(
        summary=_("Recuperar Contraseña"),
        description=_("Solicitar el cambio de contraseña"),
        request=ResetPasswordRequestSerializer,
        responses={
            200: OpenApiResponse(description=_('Correo enviado'), response=DefaultResponseSerializer),
            400: OpenApiResponse(description=_('Lo campos no son correctos'), response=DefaultResponseSerializer),
            404: OpenApiResponse(description=_('Usuario no encontrado'), response=DefaultResponseSerializer)
        },
        methods=["post"]
    )
    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                user.send_password_reset_email()
                return Response({"detail": _("Correo enviado")}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'detail': _('No existe un usuario con este correo')}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'detail': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(tags=['Autenticacion'])
class LogoutAPIView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary=_("Cerrar la sesion"),
        description=_("Cerrar la sesión"),
        request=LogoutSerializer,
        methods=["post"],
        responses={
            200: OpenApiResponse(description=_('Cierre de sesión exitoso')),
            401: OpenApiResponse(description=_('Usted no tiene permiso para ver este usuario')),
        },
    )
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh_token"]
            print(refresh_token)
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'detail': _('Sesión cerrada correctamente')}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(tags=['Autenticacion'])
class CustomObtainTokenPairWithView(TokenObtainPairView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = CustomTokenObtainPairSerializer

    @extend_schema(
        summary=_("Iniciar sesion"),
        description=_("Iniciar Sesión"),
        responses={200: TokenOutput},
        methods=["post"]
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(tags=['Autenticacion'], summary=_("Generar un nuevas credenciales de sesion"), description=_("Se generan nuevas credenciales de sesion con las credenciales anteriores"))
class CustomTokenRefreshView(TokenRefreshView):
    pass

