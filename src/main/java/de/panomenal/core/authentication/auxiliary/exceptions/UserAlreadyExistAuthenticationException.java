package de.panomenal.core.authentication.auxiliary.exceptions;

public class UserAlreadyExistAuthenticationException extends RuntimeException {
    public UserAlreadyExistAuthenticationException(String message) {
        super(message);
    }
}