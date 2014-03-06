from _ssl import SSLError
import json
import urllib
from urllib2 import URLError
from django.conf import settings
from django.core.files import File
import oauth2
from social_auth.db.django_models import UserSocialAuth
from manticore_tastypie_user.manticore_tastypie_user.resources import User


def social_auth_user(backend, uid, user=None, *args, **kwargs):
    """Return UserSocialAuth account for backend/uid pair or None if it
    doesn't exists.

    Delete UserSocialAuth if UserSocialAuth entry belongs to another
    user.
    """
    social_user = UserSocialAuth.get_social_auth(backend.name, uid)
    if social_user:
        if user and social_user.user != user:
            # Delete UserSocialAuth pairing so this account can now connect
            social_user.delete()
            social_user = None
        elif not user:
            user = social_user.user
    return {'social_user': social_user,
            'user': user,
            'new_association': False}