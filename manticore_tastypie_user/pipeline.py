from _ssl import SSLError
import json
from social.apps.django_app.default.models import UserSocialAuth
import urllib
from urllib2 import URLError
from django.conf import settings
from django.core.files import File
import oauth2


def social_auth_user(strategy, uid, user=None, *args, **kwargs):
    """Return UserSocialAuth account for backend/uid pair or None if it
    doesn't exists.

    Delete UserSocialAuth if UserSocialAuth entry belongs to another
    user.
    """
    social = UserSocialAuth.get_social_auth(strategy.backend.name, uid)
    if social:
        if user and social.user != user:
            # Delete UserSocialAuth pairing so this account can now connect
            social.delete()
            social = None
        elif not user:
            user = social.user
    return {'social': social,
            'user': user,
            'is_new': user is None,
            'new_association': False}


def get_profile_image(strategy, details, response, uid, user, social, *args, **kwargs):
    """Attempt to get a profile image for the User"""

    if user is None:
        return

    # Save photo from FB
    if strategy.backend.name == "facebook":
        try:
            image_url = "https://graph.facebook.com/%s/picture?type=large" % uid
            result = urllib.urlretrieve(image_url)

            done, tries = False, 0
            while not done:
                try:
                    user.original_photo.save("%s.jpg" % uid, File(open(result[0])))
                    user.save(update_fields=['original_photo'])
                    done = True
                except SSLError:
                    pass

                # Try at max, 10 times before quitting
                tries += 1
                if tries > 10:
                    done = True
        except URLError:
            pass
    elif strategy.backend.name == "twitter" and social:
        try:
            # Get profile image to save
            if response['profile_image_url'] != '':
                image_result = urllib.urlretrieve(response['profile_image_url'])

                done, tries = False, 0
                while not done:
                    try:
                        user.original_photo.save("%s.jpg" % uid, File(open(image_result[0])))
                        user.save(update_fields=['original_photo'])
                        done = True
                    except SSLError:
                        pass

                    # Try at max, 10 times before quitting
                    tries += 1
                    if tries > 10:
                        done = True
        except URLError:
            pass