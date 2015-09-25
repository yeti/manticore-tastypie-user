from _ssl import SSLError
import json
import urllib
from urllib2 import URLError
from django.conf import settings
from django.core.files import File
import oauth2
from social_auth.db.django_models import UserSocialAuth
from manticore_tastypie_user.manticore_tastypie_user.resources import UserProfile


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


def create_user_profile(backend, details, response, uid, user=None, social_user=None, *args, **kwargs):
    """Create a UserProfile for the User"""

    if user is None:
        return

    try:
        user.userprofile
    except UserProfile.DoesNotExist:
        user_profile = UserProfile(user=user)
        user_profile.save()

        # TODO: profile picture urls are already included in the 'response' object

        # Save photo from FB
        if backend.name == "facebook":
            try:
                image_url = "https://graph.facebook.com/%s/picture?type=large" % uid
                result = urllib.urlretrieve(image_url)

                done, tries = False, 0
                while not done:
                    try:
                        user_profile.original_photo.save("%s.jpg" % uid, File(open(result[0])))
                        user_profile.save(update_fields=['original_photo'])
                        done = True
                    except SSLError:
                        pass

                    # Try at max, 10 times before quitting
                    tries += 1
                    if tries > 10:
                        done = True
            except URLError:
                pass
        elif backend.name == "twitter" and social_user:
            try:
                # Get user info from twitter
                user_url = "http://api.twitter.com/1.1/users/show.json?user_id=%s&include_entities=false" % uid
                consumer = oauth2.Consumer(settings.TWITTER_CONSUMER_KEY, settings.TWITTER_CONSUMER_SECRET)
                token = oauth2.Token(social_user.tokens['oauth_token'], social_user.tokens['oauth_token_secret'])
                client = oauth2.Client(consumer, token)
                resp, content = client.request(user_url)
                twitter_user = json.loads(content)

                # Get profile image to save
                if twitter_user['profile_image_url'] != '':
                    image_result = urllib.urlretrieve(twitter_user['profile_image_url'])

                    done, tries = False, 0
                    while not done:
                        try:
                            user_profile.original_photo.save("%s.jpg" % uid, File(open(image_result[0])))
                            user_profile.save(update_fields=['original_photo'])
                            done = True
                        except SSLError:
                            pass

                        # Try at max, 10 times before quitting
                        tries += 1
                        if tries > 10:
                            done = True
            except URLError:
                pass