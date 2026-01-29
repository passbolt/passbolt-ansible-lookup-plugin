import jsonschema
import requests

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_request import APIRequest
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_response import APIResponse
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.exceptions.api_format_exception import \
    APIFormatException


class HTTPClientService(object):

    API_RESPONSE_SCHEMA = {
        "type": "object",
        "required": [
            "header",
            "body"
        ],
        "properties": {
            "header": {
                "type": "object"
            },
            "body": {
                "type": ["object", "array", "string", "null"]
            }
        }
    }

    @classmethod
    def send(cls, api_request: APIRequest) -> APIResponse:
        headers = {}
        if api_request.auth_credentials is not None:
            headers |= api_request.auth_credentials.headers()

        if api_request.body is None:
            result = requests.request(api_request.method.value, api_request.uri, headers=headers,
                                      verify=api_request.verify, timeout=api_request.timeout)
        else:
            result = requests.request(api_request.method.value, api_request.uri, headers=headers, json=api_request.body,
                                      verify=api_request.verify, timeout=api_request.timeout)

        if result.headers.get("Content-Type") != "application/json":
            return APIResponse(result.status_code, dict(result.headers), None)

        try:
                json_result = result.json()
        except requests.exceptions.JSONDecodeError:
            raise APIFormatException("The API returned invalid JSON data.")

        try:
            jsonschema.validate(json_result, cls.API_RESPONSE_SCHEMA)
        except jsonschema.ValidationError as e:
            raise APIFormatException("The API returned valid JSON data but in an unexpected format: '%s'." % e)
        return APIResponse(result.status_code, dict(result.headers), json_result)
