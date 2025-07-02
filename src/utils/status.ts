enum Status {
  // Success-related statuses
  SUCCESS = 'success', // Operation was successful
  CREATED = 'created', // Resource was created successfully
  ACCEPTED = 'accepted', // Request has been accepted for processing

  // Failure/Error-related statuses
  FAIL = 'fail', // Generic failure status
  ERROR = 'error', // An error occurred during the operation
  INVALID = 'invalid', // Data or request is invalid
  UNAUTHORIZED = 'unauthorized', // Not authenticated or authorized to perform the operation
  FORBIDDEN = 'forbidden', // Operation is forbidden
  NOT_FOUND = 'not_found', // Resource could not be found
  CONFLICT = 'conflict', // There was a conflict in the request (e.g., resource already exists)
  TOO_MANY_REQUESTS = 'too_many_requests', // Rate limit exceeded

  // Pending/Processing statuses
  PENDING = 'pending', // Operation is in progress or waiting for external input
  PROCESSING = 'processing', // The request is being processed
  QUEUED = 'queued', // The request has been queued for later execution

  // Informational statuses
  INFO = 'info', // General informational message
  REDIRECT = 'redirect', // Resource has been moved (e.g., 3xx HTTP statuses)
  NOT_MODIFIED = 'not_modified', // Resource has not been modified

  // Warning-related statuses
  WARNING = 'warning', // A warning indicating potential issues
  DEPRECATED = 'deprecated', // Indicates the use of a deprecated API or resource
  UNSUPPORTED = 'unsupported', // Feature or functionality is not supported
  MAINTENANCE = 'maintenance', // Resource or service is under maintenance
  EXPIRING = 'expiring', // Resource or token is about to expire

  // Custom statuses
  CANCELLED = 'cancelled', // Operation was cancelled
  RETRY = 'retry', // Operation failed and can be retried
  BLOCKED = 'blocked', // Operation or user is blocked
  TIMEOUT = 'timeout', // Operation timed out

  // Notifications and Updates
  UPDATED = 'updated', // Resource was updated successfully
  DELETED = 'deleted', // Resource was deleted successfully
  RESET = 'reset', // Data or resource has been reset to initial state

  // System-specific statuses
  SYSTEM_FAILURE = 'system_failure', // A critical failure occurred within the system
  UNDER_LOAD = 'under_load', // The system is under high load or stress
}

export default Status;
