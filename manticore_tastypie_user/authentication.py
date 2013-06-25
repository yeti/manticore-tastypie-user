from tastypie.authentication import ApiKeyAuthentication
from tastypie.models import ApiKey


class ExpireApiKeyAuthentication(ApiKeyAuthentication):
    def get_key(self, user, api_key):
        """
        Attempts to find the API key for the user.
        """
        try:
            ApiKey.objects.get(user=user, key=api_key)
        except ApiKey.DoesNotExist:
            return self._unauthorized()

        return True