from manticore_tastypie_user.manticore_tastypie_user.resources import UserProfile

def create_user_profile(backend, details, response, user=None, is_new=False, *args, **kwargs):
    """Create a UserProfile for the User"""
    if user is None:
        return

    try:
        user.get_profile()
    except UserProfile.DoesNotExist:
        user_profile = UserProfile(user=user)
        user_profile.save()