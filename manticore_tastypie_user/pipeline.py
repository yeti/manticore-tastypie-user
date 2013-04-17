import cgi
import json
import urllib
from urllib2 import URLError
import urlparse
from django.conf import settings
from django.core.files import File
import oauth2
from manticore_tastypie_user.manticore_tastypie_user.resources import UserProfile


def create_user_profile(backend, details, response, uid, user=None, social_user=None, *args, **kwargs):
    """Create a UserProfile for the User"""
    print uid
    if user is None:
        return

    try:
        user.get_profile()
    except UserProfile.DoesNotExist:
        user_profile = UserProfile(user=user)
        user_profile.save()

        # Save photo from FB
        if backend.name == "facebook":
            try:
                image_url = "https://graph.facebook.com/%s/picture?type=large" % uid
                result = urllib.urlretrieve(image_url)
                user_profile.original_photo.save("%s.jpg" % uid, File(open(result[0])))
                user_profile.save(update_fields=['original_photo'])
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
                    user_profile.original_photo.save("%s.jpg" % uid, File(open(image_result[0])))
                    print 'original_photo saved'
                    user_profile.save(update_fields=['original_photo'])
            except URLError:
                pass