from tastypie.authorization import Authorization
from tastypie.exceptions import Unauthorized


class UserAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        return object_list.filter(pk=bundle.request.user.pk)

    def read_detail(self, object_list, bundle):
        return bundle.obj == bundle.request.user

    def create_list(self, object_list, bundle):
        return object_list.filter(pk=bundle.request.user.pk)

    def create_detail(self, object_list, bundle):
        return bundle.obj == bundle.request.user

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if obj == bundle.request.user:
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return bundle.obj == bundle.request.user

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("No DELETE")

    def delete_detail(self, object_list, bundle):
        raise Unauthorized("No DELETE")


class UserObjectsOnlyAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        return object_list.filter(user=bundle.request.user)

    def read_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user

    def create_list(self, object_list, bundle):
        return object_list.filter(user=bundle.request.user)

    def create_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if obj.user == bundle.request.user:
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("Sorry, no deletes.")

    def delete_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user


class RelateUserAuthorization(Authorization):
    """
    This authorization is used for objects that are related to an authenticated user, e.g. Comment, Like, Flag.

    All users (authenticated or not) can read_list and read_detail
    Authenticated users can also create_detail, update_list, update_detail, and delete_detail
    No users are permissioned to create_list or delete_list

    Authenticated users will have the related object automatically associated with them.
    """
    def read_list(self, object_list, bundle):
        return object_list

    def read_detail(self, object_list, bundle):
        return True

    def create_list(self, object_list, bundle):
        raise Unauthorized("Sorry, no bulk creates.")

    def create_detail(self, object_list, bundle):
        if not bundle.request.user.is_authenticated():
            raise Unauthorized("Creating requires an authenticated user.")

        bundle.obj.user = bundle.request.user
        return True

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if obj.user == bundle.request.user:
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("Sorry, no deletes.")

    def delete_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user