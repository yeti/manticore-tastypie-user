from tastypie.authorization import Authorization
from tastypie.exceptions import Unauthorized


class UserLoginAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        return object_list.filter(pk=bundle.request.user.pk)

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return bundle.obj == bundle.request.user

    def create_list(self, object_list, bundle):
        # Assuming their auto-assigned to ``user``.
        raise Unauthorized("GET only")

    def create_detail(self, object_list, bundle):
        raise Unauthorized("GET only")

    def update_list(self, object_list, bundle):
        raise Unauthorized("GET only")

    def update_detail(self, object_list, bundle):
        raise Unauthorized("GET only")

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("No DELETE")

    def delete_detail(self, object_list, bundle):
        raise Unauthorized("No DELETE")


class UserObjectsOnlyAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        return object_list.filter(user=bundle.request.user)

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return bundle.obj.user == bundle.request.user

    def create_list(self, object_list, bundle):
        # Assuming their auto-assigned to ``user``.
        return object_list

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
        return bundle.obj == bundle.request.user

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("Sorry, no deletes.")

    def delete_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user


class RelateUserAuthorization(Authorization):
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
        raise Unauthorized("Sorry, no bulk deletes.")

    def delete_detail(self, object_list, bundle):
        return bundle.obj.user == bundle.request.user