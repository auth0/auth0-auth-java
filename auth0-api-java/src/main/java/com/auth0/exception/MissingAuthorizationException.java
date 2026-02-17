package com.auth0.exception;


/**
 * Thrown when the Authorization header is missing, empty, or cannot be parsed.
 */
public class MissingAuthorizationException extends BaseAuthException {

    public MissingAuthorizationException() {
        super(
                400,
                "invalid_request",
                ""
        );
    }
}
