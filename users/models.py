from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core import validators
from django.utils.translation import gettext_lazy as _
import re




class User(AbstractUser):
    email = models.EmailField(
        _('Correo Electrónico'),
        validators=[validators.validate_email],
        unique=True,
        error_messages={
            'unique': 'A user with that email already exists.'
        }
    )
    avatar = models.ImageField(upload_to='avatar/', null=True, blank=True)
    created = models.DateTimeField(
        'created at',
        auto_now_add=True,
        help_text=_('Date time on which the object was created')
    )
    modified = models.DateTimeField(
        _('created at'),
        auto_now=True,
        help_text=_('Date time on which the object was last modified')
    )
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name']

    @classmethod
    def generate_unique_username(cls, email: str) -> str:
        # email user
        local_part = email.split('@')[0]
        username_base = re.sub(r'\W+', '', local_part).lower()
        username = username_base
        # Validate unique
        count = 1
        while User.objects.filter(username=username).exists():
            username = f"{username_base}_{count}"
            count += 1
        return username

    class Meta:
        verbose_name = _("Usuario")
        verbose_name_plural = _("Usuarios")
        get_latest_by = 'created'
        ordering = ['-created', '-modified']
