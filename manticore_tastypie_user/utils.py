from manticore_tastypie_user.manticore_tastypie_user.resources import LoginResource, SignUpResource, ChangePasswordResource, SearchUserResource, UserResource, EditUserResource, SocialSignUpResource, UserSocialAuthenticationResource, LogoutResource


# Registers this library's resources
def register_api(api):
    api.register(SignUpResource())
    api.register(LoginResource())
    api.register(ChangePasswordResource())
    api.register(SearchUserResource())
    api.register(UserResource())
    api.register(EditUserResource())
    api.register(SocialSignUpResource())
    api.register(UserSocialAuthenticationResource())
    api.register(LogoutResource())
    return api