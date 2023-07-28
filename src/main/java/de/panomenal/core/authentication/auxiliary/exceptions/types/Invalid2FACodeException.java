package de.panomenal.core.authentication.auxiliary.exceptions.types;

public class Invalid2FACodeException extends Exception {
    public Invalid2FACodeException(String message) {
        super(message);
    }
}
