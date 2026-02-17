package com.auth0.exception;

public class InvalidRequestException extends BaseAuthException {
    public InvalidRequestException(String message) {
        super(400, "invalid_request", message);
    }
}
