enum HttpStatusCode {
  // 1xx: Informational - Request received, continuing process
  CONTINUE = 100, // Request received, client should continue
  SWITCHING_PROTOCOLS = 101, // Switching to a different protocol as requested by the client
  PROCESSING = 102, // Server has received the request but is still processing
  EARLY_HINTS = 103, // Used to suggest actions to the client before the final response is available

  // 2xx: Success - The action was successfully received, understood, and accepted
  OK = 200, // Standard response for a successful HTTP request
  CREATED = 201, // Resource successfully created
  ACCEPTED = 202, // Request accepted but processing is not complete
  NON_AUTHORITATIVE_INFORMATION = 203, // The information returned may be from another source
  NO_CONTENT = 204, // Request succeeded, but no content to send back
  RESET_CONTENT = 205, // Request succeeded, and the client should reset the view
  PARTIAL_CONTENT = 206, // Partial resource delivery due to range header in the request
  MULTI_STATUS = 207, // WebDAV; used for multiple status codes in a single response
  ALREADY_REPORTED = 208, // WebDAV; indicates that the results were already reported
  IM_USED = 226, // Request fulfilled using the 'IM' content

  // 3xx: Redirection - Further action must be taken to complete the request
  MULTIPLE_CHOICES = 300, // Multiple options for the resource
  MOVED_PERMANENTLY = 301, // The resource has been moved permanently to a new URL
  FOUND = 302, // The resource has been temporarily moved to a new URL
  SEE_OTHER = 303, // Redirect to a different resource, typically using GET
  NOT_MODIFIED = 304, // Resource has not been modified since the last request
  USE_PROXY = 305, // Resource must be accessed through a proxy
  TEMPORARY_REDIRECT = 307, // Temporary redirection, but the method should not change
  PERMANENT_REDIRECT = 308, // Permanent redirection with the same HTTP method

  // 4xx: Client Errors - The request contains bad syntax or cannot be fulfilled
  BAD_REQUEST = 400, // The request cannot be processed due to bad syntax
  UNAUTHORIZED = 401, // Authentication is required and has failed or has not been provided
  PAYMENT_REQUIRED = 402, // Reserved for future use (usually related to digital payment)
  FORBIDDEN = 403, // Server understands the request, but refuses to authorize it
  NOT_FOUND = 404, // The requested resource could not be found
  METHOD_NOT_ALLOWED = 405, // The request method is not allowed for the resource
  NOT_ACCEPTABLE = 406, // The requested resource is not capable of generating acceptable content
  PROXY_AUTHENTICATION_REQUIRED = 407, // The client must authenticate with the proxy
  REQUEST_TIMEOUT = 408, // The server timed out waiting for the request
  CONFLICT = 409, // There is a conflict with the current state of the resource
  GONE = 410, // The resource is no longer available and will not be available again
  LENGTH_REQUIRED = 411, // The request did not specify the length of its content
  PRECONDITION_FAILED = 412, // One or more preconditions in the request header fields were false
  PAYLOAD_TOO_LARGE = 413, // The request is larger than the server is willing to process
  URI_TOO_LONG = 414, // The URI provided was too long for the server to process
  UNSUPPORTED_MEDIA_TYPE = 415, // The media format is not supported by the server
  RANGE_NOT_SATISFIABLE = 416, // The client asked for an invalid range of the resource
  EXPECTATION_FAILED = 417, // The server cannot meet the requirements of the Expect request header
  IM_A_TEAPOT = 418, // The server refuses to brew coffee (RFC 2324, a playful status)
  MISDIRECTED_REQUEST = 421, // The request was directed to a server that is not able to produce a response
  UNPROCESSABLE_ENTITY = 422, // WebDAV; the server understands the request but it was unable to process it
  LOCKED = 423, // WebDAV; the resource is locked
  FAILED_DEPENDENCY = 424, // WebDAV; the request failed due to a failure of a previous request
  TOO_EARLY = 425, // Server is unwilling to process a request that might be replayed
  UPGRADE_REQUIRED = 426, // The client should upgrade to a different protocol
  PRECONDITION_REQUIRED = 428, // The origin server requires the request to be conditional
  TOO_MANY_REQUESTS = 429, // The user has sent too many requests in a given amount of time (rate limiting)
  REQUEST_HEADER_FIELDS_TOO_LARGE = 431, // The server is unwilling to process the request because its header fields are too large
  UNAVAILABLE_FOR_LEGAL_REASONS = 451, // The resource is unavailable due to legal reasons

  // 5xx: Server Errors - The server failed to fulfill an apparently valid request
  INTERNAL_SERVER_ERROR = 500, // A generic error occurred on the server
  NOT_IMPLEMENTED = 501, // The server does not recognize the request method, or lacks the ability to fulfill it
  BAD_GATEWAY = 502, // The server received an invalid response from an inbound server
  SERVICE_UNAVAILABLE = 503, // The server is temporarily unable to handle the request (overloaded or down for maintenance)
  GATEWAY_TIMEOUT = 504, // The server did not receive a timely response from an upstream server
  HTTP_VERSION_NOT_SUPPORTED = 505, // The server does not support the HTTP protocol version used in the request
  VARIANT_ALSO_NEGOTIATES = 506, // The server has an internal configuration error
  INSUFFICIENT_STORAGE = 507, // WebDAV; the server is unable to store the representation needed to complete the request
  LOOP_DETECTED = 508, // WebDAV; the server detected an infinite loop while processing the request
  NOT_EXTENDED = 510, // The server requires further extensions to fulfill the request
  NETWORK_AUTHENTICATION_REQUIRED = 511, // The client needs to authenticate to gain network access
}

export default HttpStatusCode;
