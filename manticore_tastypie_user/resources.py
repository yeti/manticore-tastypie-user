import base64
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.core.validators import validate_email
from social_auth.backends import get_backend
from social_auth.db.django_models import UserSocialAuth
from tastypie import fields
from tastypie.authentication import Authentication, BasicAuthentication, MultiAuthentication
from tastypie.authorization import Authorization, ReadOnlyAuthorization
from tastypie.constants import ALL_WITH_RELATIONS
from tastypie.exceptions import BadRequest
from tastypie.models import ApiKey
from manticore_tastypie_user.manticore_tastypie_user.authentication import ExpireApiKeyAuthentication
from manticore_tastypie_user.manticore_tastypie_user.authorization import UserObjectsOnlyAuthorization
from manticore_tastypie_core.manticore_tastypie_core.resources import ManticoreModelResource, PictureVideoUploadResource


User = get_user_model()


# Helper function for User resources to create a new API Key
def _create_api_token(bundle):
    user = bundle.obj

    # Maintain one ApiKey per user
    if ApiKey.objects.filter(user=user).exists():
        api_key = ApiKey.objects.filter(user=user).all()[0]
    else:
        # Create a new api key object and return just the key for use
        api_key = ApiKey.objects.create(user=user)
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


class BaseUserResource(ManticoreModelResource):
    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        pass

    def dehydrate(self, bundle):
        for field in settings.AUTH_PROFILE_EXTRA_FIELDS:
            bundle.data[field] = getattr(bundle.obj, field, None)()

        return bundle

    def dehydrate_token(self, bundle):
        return _create_api_token(bundle)


class SignUpResource(BaseUserResource):
    """Takes in an email, username, and base64 encoded password,
    creates a user then returns an API Token for further authenticated calls"""

    token = fields.CharField(readonly=True)

    # hacky fix for birthday
    for f in User._meta.local_fields:
        if f.name == "birthday":
            birthday = fields.DateField(attribute="birthday")

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['post']
        authorization = Authorization()
        authentication = Authentication()
        resource_name = "sign_up"
        always_return_data = True
        object_name = "user"

    def obj_create(self, bundle, request=None, **kwargs):
        if not 'username' in bundle.data or not 'email' in bundle.data or not 'password' in bundle.data:
            raise BadRequest("Improper fields")

        if User.objects.filter(email=bundle.data['email']):
            raise BadRequest("That email has already been used")
        elif User.objects.filter(username__iexact=bundle.data['username']):
            raise BadRequest("That username has already been used")

        new_username = bundle.data['username']
        new_email = bundle.data['email']
        new_password = base64.decodestring(bundle.data['password'])

        if len(new_password) == 0:
            raise BadRequest("Invalid password was provided")

        try:
            validate_email(new_email)
        except ValidationError:
            raise BadRequest("Email address is not formatted properly")

        try:
            user = User.objects.create_user(new_username, new_email, new_password)
            user.save()

            bundle.obj = User(user=user)

            # Save any extra information on the user profile
            for name, value in bundle.data.iteritems():
                if value and value != getattr(bundle.obj, name, None):
                    setattr(bundle.obj, name, value)

            bundle.obj.save()
        except IntegrityError:
            raise BadRequest('That username has already been used')

        return bundle


class LoginResource(BaseUserResource):
    """Uses Basic Http Auth to login a user, then returns an API Token for further authenticated calls"""

    token = fields.CharField(readonly=True)

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = BasicAuthentication()
        resource_name = "login"
        object_name = "user"


class SocialSignUpResource(BaseUserResource):

    token = fields.CharField(readonly=True)

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['post']
        authentication = MultiAuthentication(ExpireApiKeyAuthentication(), Authentication())
        authorization = Authorization()
        resource_name = "social_sign_up"
        always_return_data = True
        object_name = "user"

    def obj_create(self, bundle, request=None, **kwargs):
        provider = bundle.data['provider']
        access_token = bundle.data['access_token']

        # If this request was made with an authenticated user, try to associate this social account with it
        user = bundle.request.user if not bundle.request.user.is_anonymous() else None

        backend = get_backend(provider, bundle.request, None)
        user = backend.do_auth(access_token, user=user)
        if user and user.is_active:
            # Set bundle obj to user profile
            bundle.obj = user
            return bundle
        else:
            raise BadRequest("Error authenticating token")


class UserSocialAuthenticationResource(ManticoreModelResource):

    class Meta:
        queryset = UserSocialAuth.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "user_social_auth"
        object_name = "user_social_auth"
        fields = ['id', 'provider']


class ChangePasswordResource(ManticoreModelResource):
    """Takes in a new_password and old_password to change a user's password"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['patch']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "change_password"
        always_return_data = True
        object_name = "user"
        excludes = ["original_photo", "small_photo", "large_photo", "thumbnail"]

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

        bundle.obj.user.save()

        return bundle

    def dispatch(self, request_type, request, **kwargs):
        # Force this to be a single User update
        return super(ChangePasswordResource, self).dispatch('detail', request, **kwargs)

    def patch_detail(self, request, **kwargs):
        # Place the authenticated user's id in the patch detail request
        kwargs['id'] = request.user.pk
        return super(ChangePasswordResource, self).patch_detail(request, **kwargs)


class SearchUserResource(BaseUserResource):
    """Used to search for another user's user profile"""

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = ReadOnlyAuthorization()
        authentication = MultiAuthentication(ExpireApiKeyAuthentication(), Authentication())
        resource_name = "search_user"
        object_name = "user"
        filtering = {
            "user": ALL_WITH_RELATIONS
        }


class UserResource(BaseUserResource):
    """Used to return an authorized user's profile information"""

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "user"
        object_name = "user"
        filtering = {
            "id": ['exact'],
            "user": ALL_WITH_RELATIONS
        }


class EditUserResource(PictureVideoUploadResource):
    """Allows the user's username and email to be changed"""

    user = fields.ToOneField(UserResource, 'user', full=True)

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['patch']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "edit_user"
        always_return_data = True
        object_name = "user"

    def save_related(self, bundle):
        user = bundle.obj.user
        if 'username' in bundle.data and bundle.data['username'] != user.username and len(bundle.data['username']) > 0:
            username = bundle.data['username'].replace(' ', '')
            if User.objects.filter(username__iexact=username):
                raise BadRequest("That username has already been used")
            else:
                user.username = username

        if 'email' in bundle.data and bundle.data['email'] != user.email and len(bundle.data['email']) > 0:
            if User.objects.filter(email=bundle.data['email']):
                raise BadRequest("That email has already been used")
            else:
                try:
                    validate_email(bundle.data['email'])
                except ValidationError:
                    raise BadRequest("Email address is not formatted properly")
                user.email = bundle.data['email']

        if 'password' in bundle.data and len(bundle.data['password']) > 0:
            user.set_password(base64.decodestring(bundle.data['password']))

        user.save()

        return super(EditUserResource, self).save_related(bundle)

    def dispatch(self, request_type, request, **kwargs):
        # Force this to be a single User update
        return super(EditUserResource, self).dispatch('detail', request, **kwargs)

    def patch_detail(self, request, **kwargs):
        # Place the authenticated user's id in the patch detail request
        kwargs['id'] = request.user.pk
        return super(EditUserResource, self).patch_detail(request, **kwargs)

    def get_detail(self, request, **kwargs):
        # Place the authenticated user's id in the get detail request
        kwargs['id'] = request.user.pk
        return super(EditUserResource, self).get_detail(request, **kwargs)


class MinimalUserResource(ManticoreModelResource):
    """Used to return minimal amount of info to identify a user's profile"""

    username = fields.CharField()

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = ReadOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "user"
        object_name = "user"
        fields = ['id', 'username']
        filtering = {
            "id": ['exact'],
            "user": ALL_WITH_RELATIONS
        }

    def dehydrate_username(self, bundle):
        return bundle.obj.username


class LogoutResource(BaseUserResource):

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = UserObjectsOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "logout"
        object_name = "logout"
        fields = ['id']

    def obj_get_list(self, bundle, **kwargs):
        filtered_list = super(LogoutResource, self).obj_get_list(bundle, **kwargs)
        if len(filtered_list) > 1:
            raise BadRequest("More than one profile found")

        # Delete all ApiKeys for this user on logout
        ApiKey.objects.filter(user=filtered_list.all()[0].user).delete()
        return filtered_list