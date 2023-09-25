from django.urls import path, include
from rest_framework import routers
from .api import UserDetailAPIView, CurrentUserAPIView, CustomObtainTokenPairWithView, \
    RegisterAPIView, LogoutAPIView, ResetPasswordRequestAPIView, ResetPasswordCodeApiView, ResetPasswordCodeVerifyApiView, ResetPasswordApiView, CustomTokenRefreshView, \
    AvatarViewSet
from users.views import activate_account, password_reset_confirm

avatar_router = routers.DefaultRouter()
avatar_router.register('', AvatarViewSet, basename='emergencies')

api_urls = ([
    path('logout/', LogoutAPIView.as_view(), name='account-auth-logout'),
    path("current/", CurrentUserAPIView.as_view(), name="get-current-account"),
    path("login/", CustomObtainTokenPairWithView.as_view(), name="account-login"),
    path("refresh/", CustomTokenRefreshView.as_view(), name="account-refresh-token"),
    path("register/", RegisterAPIView.as_view(), name="account-register"),
    path("recover-password-link/", ResetPasswordRequestAPIView.as_view(), name="recover-password"),
    path("generate-code-recover-password/", ResetPasswordCodeApiView.as_view(), name="recover-password"),
    path("validate-code/", ResetPasswordCodeVerifyApiView.as_view() , name="validate-code"),
    path("recover-password", ResetPasswordApiView.as_view(), name="Recover password code"),
    path("account/<str:username>/", UserDetailAPIView.as_view(), name="get-account-detail"),
    path('', include(avatar_router.urls)),

], 'users')

urlpatterns = [
   path('activate_account_success/', activate_account, name='activate-account'),
    path('password-reset-confirm/', password_reset_confirm, name='password-reset-confirm'),
]
