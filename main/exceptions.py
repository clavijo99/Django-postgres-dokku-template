from rest_framework.views import exception_handler
from rest_framework_simplejwt.exceptions import InvalidToken
from django.utils.translation import gettext_lazy as _



def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None and isinstance(exc, InvalidToken) and exc.default_code == 'token_not_valid':
        response.data['status_code'] = 401
        response.status_code = 401
        response.data = {"detail": _("las credenciales caducaron")}
    return response
