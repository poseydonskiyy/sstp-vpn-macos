#include "AuthorizationBridge.h"

OSStatus SSTPStartAuthorized(AuthorizationRef authorization, const char *executable, FILE **channel) {
    // Use the system administrator dialog and a per-session channel to the helper.
    char *arguments[] = { NULL };
    return AuthorizationExecuteWithPrivileges(authorization, executable, kAuthorizationFlagDefaults,
                                               arguments, channel);
}
