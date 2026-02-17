package com.auth0.validators;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidDpopProofException;
import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.models.AuthOptions;
import com.auth0.models.HttpRequestInfo;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;

public class DPoPProofValidator {

    private final AuthOptions options;
    private final ObjectMapper objectMapper = new ObjectMapper();;


    public DPoPProofValidator(AuthOptions options) {
        this.options = options;
    }

    /**
     * Validates the DPoP proof.
     *
     * @param dpopProof  The raw DPoP JWT from the DPoP header.
     * @param decodedJwtToken The access token being bound.
     * @param requestInfo HTTP request info: method and URL
     * @throws BaseAuthException if the DPoP proof is invalid.
     */
    public void validate(String dpopProof, DecodedJWT decodedJwtToken, HttpRequestInfo requestInfo)
            throws BaseAuthException {

        DecodedJWT proofJwt = decodeDPoP(dpopProof);
        validateHeader(proofJwt);
        validateSignatureAndTokenBinding(proofJwt, dpopProof, decodedJwtToken);
        validateClaims(proofJwt, requestInfo);

    }

    DecodedJWT decodeDPoP(String dpopProof) throws InvalidDpopProofException {
        try {
            return JWT.decode(dpopProof);
        } catch (Exception e) {
            throw new InvalidDpopProofException("Failed to verify DPoP proof");
        }
    }

    private void validateHeader(DecodedJWT proof) throws BaseAuthException {
        if (!"dpop+jwt".equalsIgnoreCase(proof.getType())) {
            throw new InvalidDpopProofException("Unexpected JWT 'typ' header parameter value");
        }

        if (!"ES256".equalsIgnoreCase(proof.getAlgorithm())) {
            throw new InvalidDpopProofException("Unsupported algorithm in DPoP proof");
        }
    }

    protected void validateSignatureAndTokenBinding(DecodedJWT dpopProof, String rawProof, DecodedJWT accessToken) throws BaseAuthException {
        Map<String, Object> cnf = accessToken.getClaim("cnf").asMap();

        if (cnf == null || cnf.get("jkt") == null) {
            throw new VerifyAccessTokenException("JWT Access Token has no jkt confirmation claim");
        }

        Map<String, Object> jwkMap = dpopProof.getHeaderClaim("jwk").asMap();

        if (jwkMap == null || jwkMap.isEmpty()) {
            throw new InvalidDpopProofException("Missing or invalid jwk in header");
        }

        String expectedJkt = cnf.get("jkt").toString();

        String thumbprint = calculateJwkThumbprint(jwkMap);

        // Use constant-time comparison for thumbprint validation
        if (!MessageDigest.isEqual(expectedJkt.getBytes(StandardCharsets.UTF_8), thumbprint.getBytes(StandardCharsets.UTF_8))) {
            throw new InvalidDpopProofException("DPoP proof cnf.jkt mismatch");
        }

        String athClaim = dpopProof.getClaim("ath").asString();

        if (athClaim == null || athClaim.isEmpty()) {
            throw new InvalidDpopProofException("DPoP proof missing ath claim");
        }
        String accessTokenHash = sha256Base64Url(accessToken.getToken());

        // Use constant-time comparison for access token hash validation
        if (!MessageDigest.isEqual(athClaim.getBytes(StandardCharsets.UTF_8), accessTokenHash.getBytes(StandardCharsets.UTF_8))) {
            throw new InvalidDpopProofException("DPoP Proof ath mismatch");
        }


        if (jwkMap.containsKey("d") || jwkMap.containsKey("p") || jwkMap.containsKey("q")) {
            throw new InvalidDpopProofException("Private key material found in jwk header");
        }

        if (!"EC".equals(jwkMap.get("kty"))) {
            throw new InvalidDpopProofException("Only EC keys are supported for DPoP");
        }

        if (!"P-256".equals(jwkMap.get("crv"))) {
            throw new InvalidDpopProofException("Only P-256 curve is supported");
        }

        try {
            ECPublicKey ecPublicKey = convertJwkToEcPublicKey(jwkMap);

            Algorithm alg = Algorithm.ECDSA256(ecPublicKey, null);

            JWTVerifier verifier = JWT.require(alg).build();

            verifier.verify(rawProof);

        } catch (Exception e) {
            throw new InvalidDpopProofException("JWT signature verification failed");
        }

    }

    private void validateClaims(DecodedJWT proof, HttpRequestInfo httpRequestInfo) throws BaseAuthException {

        Instant iat = proof.getClaim("iat").asInstant();
        String jti = proof.getClaim("jti").asString();

        if (!httpRequestInfo.getHttpMethod().equalsIgnoreCase(proof.getClaim("htm").asString())) {
            throw new InvalidDpopProofException("DPoP Proof htm mismatch");
        }

        if (!httpRequestInfo.getHttpUrl().equals(proof.getClaim("htu").asString())) {
            throw new InvalidDpopProofException("DPoP Proof htu mismatch");
        }

        if (jti == null || jti.trim().isEmpty()) {
            throw new InvalidDpopProofException("jti claim must not be empty");
        }

        Instant now = Instant.now();

        Instant earliestAllowed = now.minusSeconds(options.getDpopIatOffsetSeconds());
        Instant latestAllowed = now.plusSeconds(options.getDpopIatLeewaySeconds());

        if (iat.isBefore(earliestAllowed)) {
            throw new InvalidDpopProofException("DPoP Proof iat is too old");
        }

        if (iat.isAfter(latestAllowed)) {
            throw new InvalidDpopProofException("DPoP Proof iat is from the future");
        }
    }

    /**
     * Compute SHA-256 hash and encode in Base64URL
     */
     String sha256Base64Url(String value) throws BaseAuthException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidDpopProofException("Failed to hash access token for DPoP binding", e);
        }
    }

    /**
     * Compute JWK thumbprint (RFC 7638)
     */
     String calculateJwkThumbprint(Map<String, Object> jwk) throws BaseAuthException {
        try {
            // RFC 7638: keys in lexicographic order
            Map<String, String> ordered = new TreeMap<>();

            if (jwk.get("crv") == null || jwk.get("kty") == null ||
                    jwk.get("x") == null || jwk.get("y") == null) {
                throw new InvalidDpopProofException("Malformed JWK: missing required fields");
            }
            ordered.put("crv", jwk.get("crv").toString());
            ordered.put("kty", jwk.get("kty").toString());
            ordered.put("x", jwk.get("x").toString());
            ordered.put("y", jwk.get("y").toString());

            String serialized = objectMapper.writeValueAsString(ordered);
            return sha256Base64Url(serialized);
        } catch (Exception e) {

            throw new InvalidDpopProofException("Failed to compute JWK thumbprint");
        }
    }

    public static ECPublicKey convertJwkToEcPublicKey(Map<String, Object> jwkMap)
            throws JwkException {

        Jwk jwk = Jwk.fromValues(jwkMap);
        return (ECPublicKey) jwk.getPublicKey();
    }
}

