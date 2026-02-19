package com.auth0.validators;

import com.auth0.exception.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthOptions;
import com.auth0.models.HttpRequestInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Full coverage tests for {@link DPoPProofValidator}
 *
 * JUnit 4 + Java 8 compatible
 */
public class DPoPProofValidatorTest {

    private AuthOptions options;
    private DPoPProofValidator validator;
    private HttpRequestInfo requestInfo;

    private ECPublicKey publicKey;
    private ECPrivateKey privateKey;

    @Before
    public void setUp() throws Exception {
        options = mock(AuthOptions.class);
        when(options.getDpopIatOffsetSeconds()).thenReturn(60L);
        when(options.getDpopIatLeewaySeconds()).thenReturn(60L);

        validator = new DPoPProofValidator(options);

        requestInfo = new HttpRequestInfo(
                "GET",
                "https://api.example.com/resource",
                new HashMap<>()
        );

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        publicKey = (ECPublicKey) kp.getPublic();
        privateKey = (ECPrivateKey) kp.getPrivate();
    }

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    @Test
    public void validate_success() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);
        String dpop = baseDpopWithAccessToken(accessToken, jwk, "GET", requestInfo.getHttpUrl(), Instant.now());

        validator.validate(dpop, accessToken, requestInfo);
    }

    @Test
    public void decodeDPoP_invalidJwt() {
        assertThatThrownBy(() ->
                validator.validate("not-a-jwt", mock(DecodedJWT.class), requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("Failed to verify DPoP proof");
    }

    @Test
    public void validate_invalidTypHeader() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);

        String dpop = JWT.create()
                .withHeader(Collections.singletonMap("typ", "wrong"))
                .withClaim("htm", "GET")
                .withClaim("htu", requestInfo.getHttpUrl())
                .withClaim("iat", Date.from(Instant.now()))
                .withClaim("jti", "jti")
                .withClaim("ath", "hash")
                .sign(Algorithm.ECDSA256(publicKey, privateKey));

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("Unexpected JWT 'typ'");
    }

    @Test
    public void validate_missingCnfJkt() throws Exception {
        DecodedJWT accessToken = JWT.decode(JWT.create().sign(Algorithm.ECDSA256(publicKey, privateKey)));
        String dpop = baseDpopWithAccessToken(accessToken, generateJwk(), "GET", requestInfo.getHttpUrl(), Instant.now());

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(VerifyAccessTokenException.class)
                .hasMessageContaining("no jkt");
    }

    @Test
    public void validate_thumbprintMismatch() throws Exception {
        KeyPair keyPair = generateEcKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        Map<String, Object> jwkMap = new HashMap<>();
        jwkMap.put("kty", "EC");
        jwkMap.put("crv", "P-256");
        jwkMap.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineX().toByteArray()));
        jwkMap.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineY().toByteArray()));

        DecodedJWT accessToken = createAccessTokenForJwk(jwkMap);

        Map<String, Object> wrongJwk = new HashMap<>();
        wrongJwk.put("kty", "EC");
        wrongJwk.put("crv", "P-256");
        wrongJwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
        wrongJwk.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));

        String dpop = baseDpopWithAccessToken(accessToken, wrongJwk, "GET", requestInfo.getHttpUrl(), Instant.now());

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("cnf.jkt mismatch");
    }

    @Test
    public void validate_missingAthClaim() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);

        Map<String, Object> header = new HashMap<>();
        header.put("typ", "dpop+jwt");
        header.put("jwk", jwk);

        String dpop = JWT.create()
                .withHeader(header)
                .withClaim("htm", "GET")
                .withClaim("htu", requestInfo.getHttpUrl())
                .withClaim("iat", Date.from(Instant.now()))
                .withClaim("jti", "jti")
                .sign(Algorithm.ECDSA256(publicKey, privateKey));

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("missing ath");
    }

    @Test
    public void validate_httpMethodMismatch() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);
        String dpop = baseDpopWithAccessToken(accessToken, jwk, "POST", requestInfo.getHttpUrl(), Instant.now());

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("htm mismatch");
    }

    @Test
    public void validate_httpUrlMismatch() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);
        String dpop = baseDpopWithAccessToken(accessToken, jwk, "GET", "https://wrong.com", Instant.now());

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("htu mismatch");
    }

    @Test
    public void validate_iatTooOld() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);
        String dpop = baseDpopWithAccessToken(accessToken, jwk, "GET", requestInfo.getHttpUrl(), Instant.now().minusSeconds(500));

        assertThatThrownBy(() ->
                validator.validate(dpop, accessToken, requestInfo)
        ).isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("iat is too old");
    }

    @Test
    public void validate_iatInFuture() throws Exception {
        Map<String, Object> jwk = generateJwk();
        DecodedJWT accessToken = createAccessTokenForJwk(jwk);

        Instant futureIat = Instant.now().plusSeconds(5000);
        String dpop = baseDpopWithAccessToken(
                accessToken,
                jwk,
                "GET",
                requestInfo.getHttpUrl(),
                futureIat
        );

        DPoPProofValidator spyValidator = Mockito.spy(validator);

        Mockito.doNothing()
                .when(spyValidator)
                .validateSignatureAndTokenBinding(
                        Mockito.any(),
                        Mockito.anyString(),
                        Mockito.any()
                );

        assertThatThrownBy(() ->
                spyValidator.validate(dpop, accessToken, requestInfo)
        )
                .isInstanceOf(InvalidDpopProofException.class)
                .hasMessageContaining("iat is from the future");
    }

    private Map<String, Object> generateJwk() {
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineX().toByteArray()));
        jwk.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineY().toByteArray()));
        return jwk;
    }

    private DecodedJWT createAccessTokenForJwk(Map<String, Object> jwk) throws Exception {
        String jkt = validator.calculateJwkThumbprint(jwk);
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jkt", jkt);

        String token = JWT.create()
                .withClaim("cnf", cnf)
                .sign(Algorithm.ECDSA256(publicKey, privateKey));

        return JWT.decode(token);
    }

    private String baseDpopWithAccessToken(DecodedJWT accessToken, Map<String, Object> jwk, String htm, String htu, Instant iat) throws Exception {
        String ath = validator.sha256Base64Url(accessToken.getToken());

        ObjectMapper mapper = new ObjectMapper();
        Map<String,Object> jwkHeader = mapper.readValue(mapper.writeValueAsString(jwk), Map.class);

        Map<String, Object> header = new HashMap<>();
        header.put("typ", "dpop+jwt");
        header.put("jwk", jwkHeader);

        return JWT.create()
                .withHeader(header)
                .withClaim("htm", htm)
                .withClaim("htu", htu)
                .withClaim("iat", Date.from(iat))
                .withClaim("jti", "jti")
                .withClaim("ath", ath)
                .sign(Algorithm.ECDSA256(publicKey, privateKey));
    }
}
