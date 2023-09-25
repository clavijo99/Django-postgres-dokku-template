import logging
import datetime
from datetime import timedelta
import jwt
from django.contrib.auth import password_validation
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
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
from .models import User, CodeRecoverPassword
from .serializers import CustomTokenObtainPairSerializer, UserModelSerializer, RegisterSerializer, TokenOutput, \
    LogoutSerializer, ResetPasswordRequestSerializer, ResetPasswordCodeValidateResponse, \
    ResetPasswordCodeValidateRequestSerializer, ResetPasswordSerializer, UserAvatarSerializer
from .views import generate_code
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


@extend_schema(tags=['authentication'])
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


@extend_schema(tags=['authentication'])
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


@extend_schema(tags=['authentication'])
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


@extend_schema(tags=['authentication'], summary=_("Generar un nuevas credenciales de sesion"),
               description=_("Se generan nuevas credenciales de sesion con las credenciales anteriores"))
class CustomTokenRefreshView(TokenRefreshView):
    pass


@extend_schema(tags=['Recover-password'])
class ResetPasswordRequestAPIView(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ResetPasswordRequestSerializer

    @extend_schema(
        summary=_("Recuperar Contraseña desde el navegador"),
        description=_("Se restablce la contraseña desde el navegador atravez de un correo"),
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


@extend_schema(tags=['Recover-password'])
class ResetPasswordCodeApiView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ResetPasswordRequestSerializer

    @extend_schema(
        summary=_("Generar codigo de seguridad para cambio de contraseña"),
        description=_("Se genera un codigo de 6 digitos con el cual se puede restablecer la contraseña"),
        request=ResetPasswordRequestSerializer,
        methods=["post"],
        responses={
            200: OpenApiResponse(description=_('Correo enviado'), response=DefaultResponseSerializer),
            400: OpenApiResponse(description=_('Lo campos no son correctos'), response=DefaultResponseSerializer),
            404: OpenApiResponse(description=_('Usuario no encontrado'), response=DefaultResponseSerializer)
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordRequestSerializer(data=request.data)
        email = request.data['email']
        if serializer.is_valid(raise_exception=False):
            try:
                user = User.objects.get(email=email)
                code = generate_code()
                expiration = timezone.now() + timedelta(minutes=30)
                code_recovery = CodeRecoverPassword.objects.create(
                    user_id=user,
                    code=code,
                    created=timezone.now(),
                    expiration=expiration
                )
                if code_recovery.pk:
                    subject = _("Restablecer Contraseña")
                    html_message = render_to_string('emails/reset_password_code.html', {
                        'code': code,
                        'first_name': user.first_name,
                    })
                    send_email = send_mail(
                        subject, '',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=False,
                        html_message=html_message)
                    if send_email > 0:
                        return Response({"detail": _("Correo enviado")}, status=status.HTTP_200_OK)
                    else:
                        return Response({'detail': _('No se logro enviar el correo')},
                                        status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({'detail': _('No existe un usuario con este correo')}, status=status.HTTP_404_NOT_FOUND)

        else:
            return Response({'detail': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(tags=['Recover-password'])
class ResetPasswordCodeVerifyApiView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ResetPasswordCodeValidateRequestSerializer

    @extend_schema(
        summary=_("Validar Codigo de seguridad para restablecer contraseña"),
        description=_("Se validad el codigo de seguridad del usuario validando si es correcto y no a caducado"),
        request=ResetPasswordCodeValidateRequestSerializer,
        responses={
            200: OpenApiResponse(description=_('Codigo valido'), response=ResetPasswordCodeValidateResponse),
            400: OpenApiResponse(description=_('Codigo caducado'), response=DefaultResponseSerializer),
            404: OpenApiResponse(description=_('Codigo no valido'), response=DefaultResponseSerializer),
        },
    )
    def post(self, request, *args, **kwargs):
        try:
            code_ = request.data['code']
            email = request.data['email']
            user = User.objects.get(email=email)
            code = CodeRecoverPassword.objects.get(code=code_, user_id=user)
            if code is not None:
                if code.expiration > timezone.now():
                    code.delete()
                    payload = {
                        'user_id': user.id,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(
                            days=settings.PASSWORD_RESET_EXPIRE_DAYS),
                        'iat': datetime.datetime.utcnow(),
                    }
                    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                    return Response({'detail': 'Codigo valido', 'token': token}, status=status.HTTP_200_OK)
                else:
                    return Response({'detail': 'El codigo a caducado'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'El correo es invalido'}, status=status.HTTP_400_BAD_REQUEST)
        except CodeRecoverPassword.DoesNotExist:
            return Response({'detail': 'Codigo invalido'}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(tags=["Recover-password"])
class ResetPasswordApiView(APIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary=_("Cambio de contraseña atravez de codigo de seguridad"),
        description=_("Se restablece la contraseña con un codigo de 6 digitos"),
        request=ResetPasswordSerializer
    )
    def post(self, request, *args, **kwargs):
        try:
            payload = jwt.decode(request.data['token'], settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            password_validation.validate_password(request.data['password'])
            encrypted_password = make_password(request.data['password'])
            user.password = encrypted_password
            user.save()
            return Response({'detail': 'El cambio de contraseña a sido exitoso!'})
        except jwt.ExpiredSignatureError:
            return Response({'detail': 'El token a caducado'})
        except jwt.DecodeError:
            return Response({'detail': 'Error del token de seguridad'})
        except User.DoesNotExist:
            return Response({'detail': 'El usuario no se encontro'})
        except ValidationError as e:
            return Response({'detal': 'La contraseña debe ser mayor a 8 caracteres y contener como minimo una letra'})
