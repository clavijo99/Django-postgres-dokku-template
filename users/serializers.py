from django.contrib.auth import authenticate, password_validation
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from users.models import User, CodeRecoverPassword
from django.utils.translation import gettext_lazy as _
from django.contrib.sites.models import Site



class UserAvatarSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField()

    class Meta:
        model = User
        fields = ['avatar']
        read_only_fields = ['id',]


class UserModelSerializer(serializers.ModelSerializer):
    avatar = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_avatar(self, user: User):  # noqa
        if user.avatar:
            return f'{Site.objects.get_current()}{user.avatar.url}'
        return ''

    class Meta:
        model = User
        fields = ('id', 'username', 'first_name',
                  'last_name', 'email', 'avatar',)


class RegisterSerializer(serializers.ModelSerializer):

    def validate(self, data):
        password = data['password']
        password_validation.validate_password(password)
        data['username'] = User.generate_unique_username(data['email'])
        data['is_active'] = False
        return data

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']


class UserLoginSerializer(serializers.Serializer):  # noqa
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)

    def validate(self, data):
        user = authenticate(username=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        if not user.is_verified:
            raise serializers.ValidationError('Account is not active yet.')
        self.context['account'] = user
        return data

    def create(self, data):
        refresh = RefreshToken.for_user(self.context['account'])
        token = {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }
        return self.context['account'], token


class UserLogoutSerializer(serializers.Serializer):  # noqa
    user = serializers.CharField()
    auth_user = serializers.CharField()

    def validate(self, data):
        if data['account'] != data['auth_user']:
            raise serializers.ValidationError('Invalid operation')
        user = User.objects.get(username=data['account'])
        self.context['account'] = user
        return data

    def save(self):
        RefreshToken.for_user(self.context['account'])


class ResetPasswordRequestSerializer(serializers.Serializer):  # noqa
    email = serializers.EmailField(required=True)


class ResetPasswordCodeRequestSerializer(serializers.Serializer):
    class Meta:
        model = CodeRecoverPassword
        fields = ('code', 'created','expiration')

class ResetPasswordCodeValidateResponse(serializers.Serializer):
    detail = serializers.CharField()
    token = serializers.CharField()



class ResetPasswordCodeValidateRequestSerializer(serializers.Serializer):
    code = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField()
    token = serializers.CharField()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):  # noqa
    @classmethod
    def get_token(cls, user):
        token = super(CustomTokenObtainPairSerializer, cls).get_token(user)
        # Add custom claims
        token["account"] = UserModelSerializer(user, many=False).data
        return token


class TokenOutput(serializers.Serializer):  # noqa
    refresh = serializers.CharField(label=_("Refresh token"))
    access = serializers.CharField(label=_("Access token"))


class LogoutSerializer(serializers.Serializer):  # noqa
    refresh_token = serializers.CharField()
