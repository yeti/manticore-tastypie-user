from datetime import timedelta
from tastypie.authentication import ApiKeyAuthentication
from tastypie.models import ApiKey
from tastypie.utils import now


class ExpireApiKeyAuthentication(ApiKeyAuthentication):
    def get_key(self, user, api_key):
        """
        Attempts to find the API key for the user. Checks if it is still valid.
        """
        try:
            api_key_obj = ApiKey.objects.get(user=user, key=api_key)
        except ApiKey.DoesNotExist:
            return self._unauthorized()

        # Validate that this API Key is less than 60 days old
        return api_key_obj.created > (now() - timedelta(days=60))