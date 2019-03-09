#include "apierror.h"

const char *rtz_get_api_error(int error)
{
    switch (error) {
    case RTZ_OK:
        return "Success";
    case RTZ_ERROR_UNAUTHORIZED:
        return "Unauthorized request (wrong or missing secret/token)";
    case RTZ_ERROR_UNAUTHORIZED_PLUGIN:
        return "Unauthorized access to plugin (token is not allowed to)";
    case RTZ_ERROR_UNKNOWN:
        return "Unknown error";
    case RTZ_ERROR_TRANSPORT_SPECIFIC:
        return "Transport specific error";
    case RTZ_ERROR_MISSING_REQUEST:
        return "Missing request";
    case RTZ_ERROR_UNKNOWN_REQUEST:
        return "Unknown request";
    case RTZ_ERROR_INVALID_JSON:
        return "Invalid JSON";
    case RTZ_ERROR_INVALID_JSON_OBJECT:
        return "Invalid JSON Object";
    case RTZ_ERROR_MISSING_MANDATORY_ELEMENT:
        return "Missing mandatory element";
    case RTZ_ERROR_INVALID_REQUEST_PATH:
        return "Invalid path for this request";
    case RTZ_ERROR_SESSION_NOT_FOUND:
        return "Session not found";
    case RTZ_ERROR_HANDLE_NOT_FOUND:
        return "Handle not found";
    case RTZ_ERROR_PLUGIN_NOT_FOUND:
        return "Plugin not found";
    case RTZ_ERROR_PLUGIN_ATTACH:
        return "Error attaching plugin";
    case RTZ_ERROR_PLUGIN_MESSAGE:
        return "Error sending message to plugin";
    case RTZ_ERROR_PLUGIN_DETACH:
        return "Error detaching from plugin";
    case RTZ_ERROR_JSEP_UNKNOWN_TYPE:
        return "Unsupported JSEP type";
    case RTZ_ERROR_JSEP_INVALID_SDP:
        return "Invalid SDP";
    case RTZ_ERROR_TRICKE_INVALID_STREAM:
        return "Invalid stream";
    case RTZ_ERROR_INVALID_ELEMENT_TYPE:
        return "Invalid element type";
    case RTZ_ERROR_SESSION_CONFLICT:
        return "Session ID already in use";
    case RTZ_ERROR_UNEXPECTED_ANSWER:
        return "Unexpected ANSWER (no OFFER)";
    case RTZ_ERROR_TOKEN_NOT_FOUND:
        return "Token not found";
    default:
        return "Unknown error";
    }
}
