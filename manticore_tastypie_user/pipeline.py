import urllib
from urllib2 import URLError
from django.core.files import File
from manticore_tastypie_user.manticore_tastypie_user.resources import UserProfile


def create_user_profile(backend, details, response, uid, user=None, is_new=False, *args, **kwargs):
    """Create a UserProfile for the User"""

    if user is None:
        return

    try:
        user.get_profile()
    except UserProfile.DoesNotExist:
        user_profile = UserProfile(user=user)

        # Save photo from FB
        if backend.name == "facebook":
            try:
                image_url = "https://graph.facebook.com/%s/picture?type=large" % uid
                result = urllib.urlretrieve(image_url)
                user_profile.original_photo.save("%s.jpg" % uid, File(open(result[0])))
            except URLError:
                pass

        user_profile.save()