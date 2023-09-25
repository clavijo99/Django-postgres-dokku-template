import datetime
import re
import jwt
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.sites.models import Site
from django.core.mail import send_mail
from django.db import models
from django.db.models.signals import post_save
from django.core import validators
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    email = models.EmailField(
        _('Correo Electrónico'),
        validators=[validators.validate_email],
        unique=True,
        error_messages={
            'unique': 'A account with that email already exists.'
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
    activation_token = models.CharField(max_length=128, null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name']

    @classmethod
    def generate_unique_username(cls, email: str) -> str:
        # email account
        local_part = email.split('@')[0]
        username_base = re.sub(r'\W+', '', local_part).lower()
        username = username_base
        # Validate unique
        count = 1
        while User.objects.filter(username=username).exists():
            username = f"{username_base}_{count}"
            count += 1
        return username

    def send_activation_email(self):
        if not self.is_active:
            domain = Site.objects.get_current().domain
            activation_token = self.create_reset_token()
            activation_link = f"{domain}/account/activate_account_success/?reset_token={activation_token}"
            subject = _("Activación de cuenta")
            html_message = render_to_string('emails/account_verification.html', {
                'first_name': self.first_name,
                'activation_link': activation_link
            })
            send_mail(
                subject, '',
                settings.DEFAULT_FROM_EMAIL,
                [self.email],
                fail_silently=False,
                html_message=html_message
            )

    def create_reset_token(self): # noqa
        payload = {
            'user_id': self.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=settings.PASSWORD_RESET_EXPIRE_DAYS),
            'iat': datetime.datetime.utcnow(),
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    def send_password_reset_email(self):
        if self.is_active:

            domain = Site.objects.get_current().domain
            reset_token = self.create_reset_token()

            activation_link = f"{domain}/account/password-reset-confirm/?reset_token={reset_token}"
            subject = _("Restablecer Contraseña")
            html_message = render_to_string('emails/reset_password.html', {
                'first_name': self.first_name,
                'activation_link': activation_link
            })
            send_mail(
                subject, '',
                settings.DEFAULT_FROM_EMAIL,
                [self.email],
                fail_silently=False,
                html_message=html_message)

    def save(self, *args, **kwargs):
        # if account is new and not has username
        if self.pk is None:
            self.activation_token = get_random_string(128)
            self.is_active = False
            self.username = User.generate_unique_username(self.email)
        super(User, self).save(*args, **kwargs)

    class Meta:
        verbose_name = _("Usuario")
        verbose_name_plural = _("Usuarios")
        get_latest_by = 'created'
        ordering = ['-created', '-modified']


@receiver(post_save, sender=User)
def send_activation_email(sender, instance: User, created, **kwargs):
    if created:
        instance.send_activation_email()



class CodeRecoverPassword(models.Model):
    code = models.IntegerField(verbose_name=_('Codigo de seguridad'), null=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_created=True)
    expiration = models.DateTimeField(verbose_name=_('tiempo de valido  del codigo'), null=False)

    class Meta:
        verbose_name = _('Codigo de seguridad restablecimiento de contraseña')
        verbose_name_plural = _('Codigos de seguridad restablecimiento de contraseñas')
