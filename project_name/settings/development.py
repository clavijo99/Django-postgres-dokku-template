from .common import *
import dj_database_url


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'p3gm=o9o+_r(5*o$$kn#h*8#n1r)aquf^^nm_v5u0pn^qa$=4*'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
ALLOWED_HOSTS = [ "http://0.0.0.0:8000/" , '*']
CSRF_TRUSTED_ORIGINS = ["http://0.0.0.0:8000"]

PASSWORD_RESET_EXPIRE_DAYS = 1




# CORS Config: install django-cors-headers and uncomment the following to allow CORS from any origin
"""
DEV_APPS = [
    'corsheaders'
]

INSTALLED_APPS += DEV_APPS

DEV_MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware'
]

MIDDLEWARE = MIDDLEWARE + DEV_MIDDLEWARE  # CORS middleware should be at the top of the list

CORS_ORIGIN_ALLOW_ALL = True
"""



# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

# Configured with DATABASE_URL env, usually from dokku
if os.environ.get('DATABASE_URL', ''):
    DATABASES = {
        'default': dj_database_url.config()
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'postgres',
            'USER': 'postgres',
            'PASSWORD': 'postgres',
            'HOST': 'db',
            'PORT': 5432,
        }
    }


EMAIL_HOST = os.environ.setdefault('EMAIL_HOST', '')
EMAIL_PORT = os.environ.setdefault('EMAIL_PORT', '')
EMAIL_HOST_USER = os.environ.setdefault('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.setdefault('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = True
