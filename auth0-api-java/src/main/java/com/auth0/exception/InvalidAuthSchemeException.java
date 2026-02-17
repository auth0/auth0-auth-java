package com.auth0.exception;

/**
 * Thrown when the Authorization header contains an unsupported
 * authentication scheme (e.g., Basic, Digest, Token, etc.).
 */
public class InvalidAuthSchemeException extends BaseAuthException {

    public InvalidAuthSchemeException(String message) {
        super(400, "invalid_request", message);
    }

    public InvalidAuthSchemeException() {
        super(400, "invalid_request", "");
    }

}
