package com.auth0.exception;

import java.util.HashMap;
import java.util.Map;

public abstract class BaseAuthException extends Exception {

    protected final int statusCode;
    protected final String errorCode;
    protected final String errorDescription;

    protected final Map<String, String> headers = new HashMap<>();

    protected BaseAuthException(
            int statusCode,
            String errorCode,
            String message
    ) {
        super(message);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.errorDescription = message;
    }

    protected BaseAuthException(int statusCode, String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.errorDescription = message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void addHeader(String name, String value) {
        headers.put(name, value);
    }
}
