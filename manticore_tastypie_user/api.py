import base64
from django.contrib.auth.models import User
from django.db import IntegrityError
from mezzanine.accounts import get_profile_model
from tastypie import fields
from tastypie.authentication import Authentication, BasicAuthentication, OAuthAuthentication
from tastypie.authorization import Authorization, ReadOnlyAuthorization
from tastypie.constants import ALL_WITH_RELATIONS
from tastypie.exceptions import BadRequest
from manticore_tastypie_user.manticore_tastypie_user.authorization import UserObjectsOnlyAuthorization
from manticore_tastypie_core.manticore_tastypie_core.resources import ManticoreModelResource


UserProfile = get_profile_model()


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
    token = fields.CharField(attribute='create_api_token')

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['post']
        authorization = Authorization()
        authentication = Authentication()
        resource_name = "sign_up"
        always_return_data = True
        object_name = "user_profile"

    def obj_create(self, bundle, request=None, **kwargs):
        if User.objects.filter(email = bundle.data['email']):
            raise BadRequest("That email has already been used")
        elif User.objects.filter(username__iexact = bundle.data['username']):
            raise BadRequest("That username has already been used")

        try:
            user = User.objects.create_user(bundle.data['username'], bundle.data['email'], base64.decodestring(bundle.data['password']))
            user.save()

            bundle.obj = UserProfile(user=user)
            bundle.obj.save()
        except IntegrityError:
            raise BadRequest('That username has already been used')

        return bundle


class LoginResource(ManticoreModelResource):
    """Uses Basic Http Auth to login a user, then returns an API Token for further authenticated calls"""

    user = fields.ToOneField(UserResource, 'user', full=True)
    token = fields.CharField(attribute='create_api_token')

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = BasicAuthentication()
        resource_name = "login"
        object_name = "user_profile"


class ResetPasswordResource(ManticoreModelResource):
    """Takes in a new_password and old_password to change a user's password"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['patch']
        authorization = UserObjectsOnlyAuthorization()
        authentication = OAuthAuthentication()
        resource_name = "reset_password"
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
        return super(ResetPasswordResource, self).dispatch('detail', request, **kwargs)

    def patch_detail(self, request, **kwargs):
        # Place the authenticated user's id in the patch detail request
        kwargs['id'] = request.user.get_profile().pk
        return super(ResetPasswordResource, self).patch_detail(request, **kwargs)


class SearchUserProfileResource(ManticoreModelResource):
    """Used to search for another's user profile"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['get']
        authorization = ReadOnlyAuthorization()
        authentication = OAuthAuthentication()
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
        authentication = OAuthAuthentication()
        resource_name = "user_profile"
        object_name = "user_profile"
        filtering = {
            "user": ALL_WITH_RELATIONS
        }

class EditUserProfileResource(ManticoreModelResource):
    """Allows the user's username and email to be changed"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = UserProfile.objects.all()
        allowed_methods = ['patch']
        authorization = UserObjectsOnlyAuthorization()
        authentication = OAuthAuthentication()
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