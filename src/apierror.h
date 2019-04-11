#pragma once

/** Success (no error) */
#define RTZ_OK								0

/** Unauthorized (can only happen when using apisecret/auth token) */
#define RTZ_ERROR_UNAUTHORIZED				403
/** Unauthorized access to a plugin (can only happen when using auth token) */
#define RTZ_ERROR_UNAUTHORIZED_PLUGIN			405
/** Unknown/undocumented error */
#define RTZ_ERROR_UNKNOWN						490
/** Transport related error */
#define RTZ_ERROR_TRANSPORT_SPECIFIC			450
/** The request is missing in the message */
#define RTZ_ERROR_MISSING_REQUEST				452
/** The request is not supported */
#define RTZ_ERROR_UNKNOWN_REQUEST				453
/** The payload is not a valid JSON message */
#define RTZ_ERROR_INVALID_JSON				454
/** The object is not a valid JSON object as expected */
#define RTZ_ERROR_INVALID_JSON_OBJECT			455
/** A mandatory element is missing in the message */
#define RTZ_ERROR_MISSING_MANDATORY_ELEMENT	456
/** The request cannot be handled for this webserver path  */
#define RTZ_ERROR_INVALID_REQUEST_PATH		457
/** The session the request refers to doesn't exist */
#define RTZ_ERROR_SESSION_NOT_FOUND			458
/** The handle the request refers to doesn't exist */
#define RTZ_ERROR_HANDLE_NOT_FOUND			459
/** The plugin the request wants to talk to doesn't exist */
#define RTZ_ERROR_PLUGIN_NOT_FOUND			460
/** An error occurring when trying to attach to a plugin and create a handle  */
#define RTZ_ERROR_PLUGIN_ATTACH				461
/** An error occurring when trying to send a message/request to the plugin */
#define RTZ_ERROR_PLUGIN_MESSAGE				462
/** An error occurring when trying to detach from a plugin and destroy the related handle  */
#define RTZ_ERROR_PLUGIN_DETACH				463
/** The SDP type is not supported */
#define RTZ_ERROR_JSEP_UNKNOWN_TYPE			464
/** The Session Description provided by the peer is invalid */
#define RTZ_ERROR_JSEP_INVALID_SDP			465
/** The stream a trickle candidate for does not exist or is invalid */
#define RTZ_ERROR_TRICKE_INVALID_STREAM		466
/** A JSON element is of the wrong type (e.g., an integer instead of a string) */
#define RTZ_ERROR_INVALID_ELEMENT_TYPE		467
/** The ID provided to create a new session is already in use */
#define RTZ_ERROR_SESSION_CONFLICT			468
/** We got an ANSWER to an OFFER we never made */
#define RTZ_ERROR_UNEXPECTED_ANSWER			469
/** The auth token the request refers to doesn't exist */
#define RTZ_ERROR_TOKEN_NOT_FOUND				470
/** The current request cannot be handled because of not compatible WebRTC state */
#define RTZ_ERROR_WEBRTC_STATE				471


/** Helper method to get a string representation of an API error code
 * @param[in] error The API error code
 * @returns A string representation of the error code */
const char *rtz_get_api_error(int error);
