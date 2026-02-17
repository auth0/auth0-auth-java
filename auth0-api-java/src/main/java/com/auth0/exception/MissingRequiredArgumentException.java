package com.auth0.exception;

/**
 * Thrown when a required argument is missing, such as a required header
 * (Authorization, DPoP, etc.) or an expected field inside a JWT.
 */
public class MissingRequiredArgumentException extends BaseAuthException {

    public MissingRequiredArgumentException(String argumentName) {
        super(
                400,
                "invalid_request",
                "The required argument '" + argumentName + "' was not provided."
        );
    }

    public MissingRequiredArgumentException() {
        super(
                400,
                "invalid_request",
                ""
        );
    }
}