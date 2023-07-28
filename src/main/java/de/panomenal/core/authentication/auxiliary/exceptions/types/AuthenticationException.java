package de.panomenal.core.authentication.auxiliary.exceptions.types;

public class AuthenticationException extends RuntimeException {

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
