from manticore_tastypie_user.manticore_tastypie_user.resources import LoginResource, SignUpResource, \
    ChangePasswordResource, SearchUserResource, UserResource, EditUserResource, LogoutResource, MyUserResource, \
    ForgotPasswordResource


# Registers this library's resources
def register_api(api):
    api.register(SignUpResource())
    api.register(LoginResource())
    api.register(ChangePasswordResource())
    api.register(SearchUserResource())
    api.register(EditUserResource())
    api.register(UserResource())
    api.register(MyUserResource())
    api.register(LogoutResource())
    api.register(ForgotPasswordResource())
    return api