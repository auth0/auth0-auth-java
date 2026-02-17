package com.auth0.exception;


/**
 * Thrown when a DPoP proof (DPoP: header) is malformed, invalid,
 * fails signature verification, has wrong JWK thumbprint, wrong method,
 * wrong URI, expired jti, replay, or contains multiple proofs.
 */
public class InvalidDpopProofException extends BaseAuthException {

    public InvalidDpopProofException(String message) {
        super(
                400,
                "invalid_dpop_proof",
                message
        );
    }

    public InvalidDpopProofException(String message, Throwable cause) {
        // Calls the new BaseAuthException constructor with the cause
        super(400, "invalid_dpop_proof", message, cause);
    }
}
