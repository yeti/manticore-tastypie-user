from manticore_tastypie_user.manticore_tastypie_user.resources import LoginResource, SignUpResource, ChangePasswordResource, SearchUserProfileResource, UserProfileResource, EditUserProfileResource, SocialSignUpResource


# Registers this library's resources
def register_api(api):
    api.register(SignUpResource())
    api.register(LoginResource())
    api.register(ChangePasswordResource())
    api.register(SearchUserProfileResource())
    api.register(UserProfileResource())
    api.register(EditUserProfileResource())
    api.register(SocialSignUpResource())
    return api