package org.sid.userManagement_service.exception;

public class InvalidCredentialsException  extends AuthenticationException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
}