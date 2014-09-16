import base64
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.core.validators import validate_email
from tastypie import fields
from tastypie.authentication import Authentication, BasicAuthentication, MultiAuthentication
from tastypie.authorization import Authorization, ReadOnlyAuthorization
from tastypie.exceptions import BadRequest
from tastypie.fields import ToManyField
from tastypie.models import ApiKey
from manticore_tastypie_user.manticore_tastypie_user.authentication import ExpireApiKeyAuthentication
from manticore_tastypie_user.manticore_tastypie_user.authorization import UserAuthorization
from manticore_tastypie_core.manticore_tastypie_core.resources import ManticoreModelResource, PictureVideoUploadResource
import settings


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


class BaseUserResource(ManticoreModelResource):

    class Meta:
        excludes = ['password', 'date_joined', 'is_active', 'is_staff', 'is_superuser', 'last_login']
        allowed_methods = ['get']
        filtering = {
            User.USERNAME_FIELD: ['exact', 'iexact', 'contains', 'icontains']
        }

    def dehydrate(self, bundle):
        for field in settings.USER_EXTRA_FIELDS:
            bundle.data[field] = getattr(bundle.obj, field, None)()

        return bundle

    def dehydrate_token(self, bundle):
        return _create_api_token(bundle)


class UserResource(BaseUserResource):

    class Meta:
        queryset = User.objects.all()
        resource_name = "user"
        excludes = ['password', 'date_joined', 'is_active', 'is_staff', 'is_superuser', 'last_login']
        object_name = "users"
        allowed_methods = ['get']
        filtering = {
            User.USERNAME_FIELD: ['exact', 'iexact', 'contains', 'icontains']
        }


class AuthUserResource(BaseUserResource):
    token = fields.CharField(readonly=True)

    @classmethod
    def get_fields(cls, fields=None, excludes=None):
        """ Only add the default_social_providers field if the social library is installed """
        this_class = next(c for c in cls.__mro__ if c.__module__ == __name__ and c.__name__ == 'AuthUserResource')
        final_fields = super(this_class, cls).get_fields(fields=fields, excludes=excludes)
        if 'manticore_tastypie_social.manticore_tastypie_social' in settings.INSTALLED_APPS:
            resource = 'manticore_tastypie_social.manticore_tastypie_social.resources.SocialProviderResource'
            final_fields['default_social_providers'] = ToManyField(resource, 'default_social_providers',
                                                                   null=True, full=True)
        return final_fields


class SignUpResource(AuthUserResource):
    """
    Takes in an email, base64 encoded password and the UserModel's USERNAME_FIELD,
    creates a user then returns an API Token for further authenticated calls.
    """

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['post']
        authorization = Authorization()
        authentication = Authentication()
        resource_name = "sign_up"
        always_return_data = True
        object_name = "user"

    def obj_create(self, bundle, request=None, **kwargs):
        if not User.USERNAME_FIELD in bundle.data or not 'email' in bundle.data or not 'password' in bundle.data:
            raise BadRequest("Improper fields")

        email = bundle.data['email'].lower()
        username_field_filter = {"{0}__iexact".format(User.USERNAME_FIELD): bundle.data[User.USERNAME_FIELD]}
        if User.objects.filter(email=email):
            raise BadRequest("That email has already been used")
        elif User.objects.filter(**username_field_filter):
            raise BadRequest("That {0} has already been used".format(User.USERNAME_FIELD))

        user_kwargs = {
            User.USERNAME_FIELD: bundle.data[User.USERNAME_FIELD]
        }

        password = base64.decodestring(bundle.data['password'])
        if len(password) == 0:
            raise BadRequest("Invalid password was provided")

        user_kwargs['password'] = password

        try:
            validate_email(email)
        except ValidationError:
            raise BadRequest("Email address is not formatted properly")

        user_kwargs['email'] = email

        try:
            user = User.objects.create_user(**user_kwargs)
            user.save()

            bundle.obj = user

            # Save any extra information
            used_fields = [User.USERNAME_FIELD, 'email', 'password']
            for name, value in bundle.data.iteritems():
                if value and value != getattr(bundle.obj, name, None) and name not in used_fields:
                    setattr(bundle.obj, name, value)

            bundle.obj.save()
        except IntegrityError:
            raise BadRequest('That {0} has already been used'.format(User.USERNAME_FIELD))

        return bundle


class LoginResource(AuthUserResource):
    """Uses Basic Http Auth to login a user, then returns an API Token for further authenticated calls"""

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = UserAuthorization()
        authentication = BasicAuthentication()
        resource_name = "login"
        object_name = "user"


class ChangePasswordResource(BaseUserResource):
    """Takes in a new_password and old_password to change a user's password"""

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['patch']
        authorization = UserAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "change_password"
        always_return_data = True
        object_name = "user"

    def hydrate(self, bundle):
        if not 'new_password' in bundle.data:
            raise BadRequest("No new password specified")

        if bundle.obj.password:
            if not 'old_password' in bundle.data:
                raise BadRequest("No old password specified when user has an existing password")
            elif not bundle.obj.check_password(base64.decodestring(bundle.data['old_password'])):
                raise BadRequest('old password does not match')

            bundle.obj.set_password(base64.decodestring(bundle.data['new_password']))
        else:
            bundle.obj.set_password(base64.decodestring(bundle.data['new_password']))

        bundle.obj.save()

        return bundle

    def dispatch(self, request_type, request, **kwargs):
        # Force this to be a single User update
        return super(ChangePasswordResource, self).dispatch('detail', request, **kwargs)

    def patch_detail(self, request, **kwargs):
        # Place the authenticated user's id in the patch detail request
        kwargs['id'] = request.user.pk
        return super(ChangePasswordResource, self).patch_detail(request, **kwargs)


class SearchUserResource(BaseUserResource):
    """Used to search for another user"""

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = ReadOnlyAuthorization()
        authentication = MultiAuthentication(ExpireApiKeyAuthentication(), Authentication())
        resource_name = "search_user"
        object_name = "user"
        filtering = {
            "id": ['exact'],
            User.USERNAME_FIELD: ['exact', 'iexact', 'contains', 'icontains']
        }

    def dehydrate(self, bundle):
        bundle = super(SearchUserResource, self).dehydrate(bundle)

        if bundle.request.user.is_authenticated() and \
                str(bundle.obj.pk) in bundle.request.user.user_following().values_list('object_id', flat=True):
            bundle.data['following'] = True
        else:
            bundle.data['following'] = False
        return bundle


class EditUserResource(PictureVideoUploadResource, AuthUserResource):
    """Allows the UserModel's USERNAME_FIELD and email to be changed"""

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['patch']
        authorization = UserAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "edit_user"
        always_return_data = True
        object_name = "user"

    def hydrate(self, bundle):
        user = bundle.obj
        if User.USERNAME_FIELD in bundle.data and bundle.data[User.USERNAME_FIELD] != getattr(user, User.USERNAME_FIELD) and len(bundle.data[User.USERNAME_FIELD]) > 0:
            username_field = bundle.data[User.USERNAME_FIELD].replace(' ', '')
            username_field_filter = {"{0}__iexact".format(User.USERNAME_FIELD): username_field}
            if User.objects.filter(**username_field_filter):
                raise BadRequest("That {0} has already been used".format(User.USERNAME_FIELD))

        if 'email' in bundle.data and bundle.data['email'] != user.email and len(bundle.data['email']) > 0:
            if User.objects.filter(email=bundle.data['email']):
                raise BadRequest("That email has already been used")
            else:
                try:
                    validate_email(bundle.data['email'])
                except ValidationError:
                    raise BadRequest("Email address is not formatted properly")

        return bundle

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


class MyUserResource(AuthUserResource):
    """Used to return an authorized user's information"""

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = UserAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "my_user"
        object_name = "user"


class MinimalUserResource(ManticoreModelResource):
    """Used to return minimal amount of info to identify a user"""

    class Meta:
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = ReadOnlyAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "user"
        object_name = "user"
        fields = ['id', User.USERNAME_FIELD]
        filtering = {
            "id": ['exact'],
        }


class LogoutResource(BaseUserResource):

    class Meta(BaseUserResource.Meta):
        queryset = User.objects.all()
        allowed_methods = ['get']
        authorization = UserAuthorization()
        authentication = ExpireApiKeyAuthentication()
        resource_name = "logout"
        object_name = "logout"
        fields = ['id']

    def obj_get_list(self, bundle, **kwargs):
        filtered_list = super(LogoutResource, self).obj_get_list(bundle, **kwargs)
        if len(filtered_list) > 1:
            raise BadRequest("More than one profile found")

        # Delete all ApiKeys for this user on logout
        ApiKey.objects.filter(user=filtered_list.all()[0]).delete()
        return filtered_list


class ForgotPasswordResource(BaseUserResource):

    class Meta:
        queryset = User.objects.all()
        resource_name = "forgot_password"
        object_name = "forgot_password"
        allowed_methods = ['post']
        authorization = Authorization()
        authentication = Authentication()

    def obj_create(self, bundle, request=None, **kwargs):
        if not 'email' in bundle.data:
            raise BadRequest("Missing email")

        email = bundle.data['email'].lower()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise BadRequest("This user account does not exist")
        except User.MultipleObjectsReturned:
            raise BadRequest("Multiple accounts with this email address")

        form = PasswordResetForm({'email': email})
        if form.is_valid():
            opts = {
                'use_https': bundle.request.is_secure(),
                'token_generator': default_token_generator,
                'from_email': settings.DEFAULT_FROM_EMAIL,
                'email_template_name': 'registration/password_reset_email.html',
                'subject_template_name': 'registration/password_reset_subject.txt',
                'request': request,
            }
            form.save(**opts)
        else:
            raise BadRequest("Sorry, password reset failed")

        bundle.obj = user
        return bundle