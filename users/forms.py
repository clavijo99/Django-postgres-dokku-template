from django import forms
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth import password_validation
from django.utils.translation import gettext_lazy as _


class UserPasswordResetForm(SetPasswordForm):
    """Change password form."""
    new_password1 = forms.CharField(
        label=_("New password"),
        help_text=False,
        max_length=100,
        required=True,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
                'class': 'form-control mb-4',
                'placeholder': _('password'),
            }))

    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        help_text=password_validation.password_validators_help_text_html(),
        max_length=100,
        required=True,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
                'class': 'form-control mb-4',
                'placeholder': _("New password confirmation"),
            }))
