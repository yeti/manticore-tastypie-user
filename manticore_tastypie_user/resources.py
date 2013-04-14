import base64
from django.contrib.auth.models import User
from django.db import IntegrityError
from mezzanine.accounts import get_profile_model
from social_auth.backends import get_backend
from tastypie import fields
from tastypie.authentication import Authentication, BasicAuthentication
from tastypie.authorization import Authorization, ReadOnlyAuthorization
from tastypie.constants import ALL_WITH_RELATIONS
from tastypie.exceptions import BadRequest
from tastypie.models import ApiKey
from manticore_tastypie_user.manticore_tastypie_user.authentication import ExpireApiKeyAuthentication
from manticore_tastypie_user.manticore_tastypie_user.authorization import UserObjectsOnlyAuthorization
from manticore_tastypie_core.manticore_tastypie_core.resources import ManticoreModelResource, PictureUploadResource


UserProfile = get_profile_model()


# Helper function for UserProfile resources to create a new API Key
def _create_api_token(bundle):
    user_profile = bundle.obj

    # Delete existing api key for this user if it exists
    ApiKey.objects.filter(user=user_profile.user).delete()

    # Create a new api key object and return just the key for use
    api_key = ApiKey.objects.create(user=user_profile.user)
    api_key.save()
    return api_key.key


class UserResource(ManticoreModelResource):

    class Meta:
        queryset = User.objects.all()
        resource_name = "user"
        fields = ['username', 'email']
        object_name = "users"
        allowed_methods = ['get']
        filtering = {
            "username": ['exact', 'iexact', 'contains', 'icontains']
        }


class SignUpResource(ManticoreModelResource):
    """Takes in an email, username, and base64 encoded password,
    creates a user then returns an API Token for further authenticated calls"""

    user = fields.ToOneField(UserResource, 'user', full=True)
    token = fields.CharField(readonly=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['post']
        authorization = Authorization()
        authentication = Authentication()
        resource_name = "sign_up"
        always_return_data = True
        object_name = "user_profile"

    def dehydrate_token(self, bundle):
        return _create_api_token(bundle)

    def obj_create(self, bundle, request=None, **kwargs):
        if User.objects.filter(email=bundle.data['email']):
            raise BadRequest("That email has already been used")
        elif User.objects.filter(username__iexact=bundle.data['username']):
            raise BadRequest("That username has already been used")

        try:
            user = User.objects.create_user(bundle.data['username'], bundle.data['email'], base64.decodestring(bundle.data['password']))
            user.save()

            bundle.obj = UserProfile(user=user)

            # Save any extra information on the user profile
            for name, value in bundle.data.iteritems():
                if value and value != getattr(user, name, None):
                    setattr(user, name, value)

            bundle.obj.save()
        except IntegrityError:
            raise BadRequest('That username has already been used')

        return bundle


class LoginResource(ManticoreModelResource):
    """Uses Basic Http Auth to login a user, then returns an API Token for further authenticated calls"""

    user = fields.ToOneField(UserResource, 'user', full=True)
    token = fields.CharField(readonly=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = BasicAuthentication()
        resource_name = "login"
        object_name = "user_profile"

    def dehydrate_token(self, bundle):
        return _create_api_token(bundle)


#TODO: Link up multiple social auth profiles with 1 user
class SocialSignUpResource(ManticoreModelResource):

    user = fields.ToOneField(UserResource, 'user', full=True)
    token = fields.CharField(readonly=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['post']
        authentication = Authentication()
        authorization = Authorization()
        resource_name = "social_sign_up"
        always_return_data = True
        object_name = "user_profile"

    def dehydrate_token(self, bundle):
        return _create_api_token(bundle)

    def obj_create(self, bundle, request=None, **kwargs):
        provider = bundle.data['provider']
        access_token = bundle.data['access_token']

        backend = get_backend(provider, bundle.request, None)
        user = backend.do_auth(access_token)
        if user and user.is_active:
            # Set bundle obj to user profile
            bundle.obj = user.get_profile()
            return bundle
        else:
            raise BadRequest("Error authenticating token")

class ChangePasswordResource(ManticoreModelResource):
    """Takes in a new_password and old_password to change a user's password"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['patch']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "change_password"
        always_return_data = True
        object_name = "user_profile"

    def hydrate(self, bundle):
        if not bundle.data.has_key('new_password'):
            raise BadRequest("No new password specified")

        if bundle.obj.user.password:
            if not bundle.data.has_key('old_password'):
                raise BadRequest("No old password specified when user has an existing password")
            elif not bundle.obj.user.check_password(base64.decodestring(bundle.data['old_password'])):
                raise BadRequest('old password does not match')

            bundle.obj.user.set_password(base64.decodestring(bundle.data['new_password']))
        else:
            bundle.obj.user.set_password(base64.decodestring(bundle.data['new_password']))

        return bundle

    def dispatch(self, request_type, request, **kwargs):
        # Force this to be a single UserProfile update
        return super(ChangePasswordResource, self).dispatch('detail', request, **kwargs)

    def patch_detail(self, request, **kwargs):
        # Place the authenticated user's id in the patch detail request
        kwargs['id'] = request.user.get_profile().pk
        return super(ChangePasswordResource, self).patch_detail(request, **kwargs)


class SearchUserProfileResource(ManticoreModelResource):
    """Used to search for another user's user profile"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['get']
        authorization = ReadOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "search_user_profile"
        object_name = "user_profile"
        filtering = {
            "user": ALL_WITH_RELATIONS
        }


class UserProfileResource(ManticoreModelResource):
    """Used to return an authorized user's profile information"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "user_profile"
        object_name = "user_profile"
        filtering = {
            "id": ['exact'],
            "user": ALL_WITH_RELATIONS
        }


class EditUserProfileResource(PictureUploadResource):
    """Allows the user's username and email to be changed"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['patch']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "edit_user_profile"
        always_return_data = True
        object_name = "user_profile"

    def save_related(self, bundle):
        user = bundle.obj.user
        if 'username' in bundle.data and bundle.data['username'] != user.username and len(bundle.data['username']) > 0:
            username = bundle.data['username'].replace(' ', '')
            if User.objects.filter(username__iexact=username):
                raise BadRequest("That username has already been used")
            else:
                user.username = username

        if 'email' in bundle.data and len(bundle.data['email']) > 0:
            user.email = bundle.data['email']

        if 'password' in bundle.data and len(bundle.data['password']) > 0:
            user.set_password(base64.decodestring(bundle.data['password']))

        user.save()

        return super(EditUserProfileResource, self).save_related(bundle)

    def dispatch(self, request_type, request, **kwargs):
        # Force this to be a single UserProfile update
        return super(EditUserProfileResource, self).dispatch('detail', request, **kwargs)

    def patch_detail(self, request, **kwargs):
        # Place the authenticated user's id in the patch detail request
        kwargs['id'] = request.user.get_profile().pk
        return super(EditUserProfileResource, self).patch_detail(request, **kwargs)