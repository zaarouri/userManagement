package org.sid.userManagement_service.exception;

public class KeycloakUnavailableException extends RuntimeException {
    public KeycloakUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
