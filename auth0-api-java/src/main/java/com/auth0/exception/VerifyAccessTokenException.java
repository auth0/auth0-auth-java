package com.auth0.exception;

/**
 * Thrown when the access token fails validation (signature failure,
 * incorrect issuer, incorrect audience, expired, malformed, etc.).
 */
public class VerifyAccessTokenException extends BaseAuthException {

    public VerifyAccessTokenException(String message) {
        super(
                401,
                "invalid_token",
                message
        );
    }

    public VerifyAccessTokenException(String message, Throwable cause) {
        super(401, "invalid_token", message, cause);
    }
}
