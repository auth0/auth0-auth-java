package com.auth0.exception;

import java.util.Collections;
import java.util.List;

/**
 * Exception thrown when a JWT token has insufficient scope
 */
public class InsufficientScopeException extends BaseAuthException {

    public InsufficientScopeException(String message) {
        super(403, "insufficient_scope", message);
    }
}
