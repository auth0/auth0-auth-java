package com.auth0.validators;

import com.auth0.exception.InsufficientScopeException;
import com.auth0.exception.InvalidRequestException;
import com.auth0.exception.MissingRequiredArgumentException;
import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.AuthOptions;
import com.auth0.models.HttpRequestInfo;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class JWTValidatorTest {

    @Mock
    private JwkProvider jwkProvider;

    @Mock
    private Jwk jwk;

    private JWTValidator validator;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private static final String DOMAIN = "test-domain.auth0.com";
    private static final String AUDIENCE = "https://api.example.com";
    private static final String ISSUER = "https://test-domain.auth0.com/";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        publicKey = (RSAPublicKey) pair.getPublic();
        privateKey = (RSAPrivateKey) pair.getPrivate();

        AuthOptions options = new AuthOptions.Builder()
                .domain(DOMAIN)
                .audience(AUDIENCE)
                .build();

        validator = new JWTValidator(options, jwkProvider);

        when(jwk.getPublicKey()).thenReturn(publicKey);
        when(jwkProvider.get(anyString())).thenReturn(jwk);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_shouldRejectNullOptions() {
        new JWTValidator(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_shouldRejectNullJwkProvider() {
        AuthOptions options = new AuthOptions.Builder()
                .domain(DOMAIN)
                .audience(AUDIENCE)
                .build();

        new JWTValidator(options, null);
    }

    @Test
    public void validateToken_success() throws Exception {
        String token = validToken();

        DecodedJWT jwt = validator.validateToken(token, getHttpRequestInfo());

        assertThat(jwt.getIssuer()).isEqualTo(ISSUER);
        assertThat(jwt.getAudience()).contains(AUDIENCE);
        assertThat(jwt.getSubject()).isEqualTo("user");
    }

    @Test(expected = MissingRequiredArgumentException.class)
    public void validateToken_shouldRejectNullToken() throws Exception {
        validator.validateToken(null, getHttpRequestInfo());
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void validateToken_shouldRejectInvalidSignature() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        RSAPublicKey wrongKey = (RSAPublicKey) gen.generateKeyPair().getPublic();

        when(jwk.getPublicKey()).thenReturn(wrongKey);

        validator.validateToken(validToken(), getHttpRequestInfo());
    }

    @Test
    public void validateTokenWithRequiredScopes_success() throws Exception {
        String token = tokenWithScopes("read write");

        DecodedJWT jwt = validator.validateTokenWithRequiredScopes(token, getHttpRequestInfo(), "read");

        assertThat(jwt).isNotNull();
    }

    @Test(expected = InsufficientScopeException.class)
    public void validateTokenWithRequiredScopes_failure() throws Exception {
        String token = tokenWithScopes("read");

        validator.validateTokenWithRequiredScopes(token, getHttpRequestInfo(), "admin");
    }

    @Test
    public void validateTokenWithAnyScope_success() throws Exception {
        String token = tokenWithScopes("read write");

        DecodedJWT jwt = validator.validateTokenWithAnyScope(token, getHttpRequestInfo(), "admin", "write");

        assertThat(jwt).isNotNull();
    }

    @Test(expected = InsufficientScopeException.class)
    public void validateTokenWithAnyScope_failure() throws Exception {
        String token = tokenWithScopes("read");

        validator.validateTokenWithAnyScope(token, getHttpRequestInfo(), "admin");
    }

    @Test
    public void validateTokenWithClaimEquals_success() throws Exception {
        String token = tokenWithEmail("a@b.com");

        DecodedJWT jwt = validator.validateTokenWithClaimEquals(token, getHttpRequestInfo(), "email", "a@b.com");

        assertThat(jwt).isNotNull();
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void validateTokenWithClaimEquals_failure() throws Exception {
        String token = tokenWithEmail("a@b.com");

        validator.validateTokenWithClaimEquals(token, getHttpRequestInfo(), "email", "x@y.com");
    }

    @Test
    public void validateTokenWithClaimIncludes_success() throws Exception {
        String token = tokenWithScopes("read write");

        DecodedJWT jwt = validator.validateTokenWithClaimIncludes(token, getHttpRequestInfo(), "scope", "read");

        assertThat(jwt).isNotNull();
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void validateTokenWithClaimIncludes_failure() throws Exception {
        String token = tokenWithScopes("read");

        validator.validateTokenWithClaimIncludes(token, getHttpRequestInfo(), "scope", "admin");
    }

    @Test
    public void validateTokenWithClaimIncludesAny_success() throws Exception {
        String token = tokenWithScopes("read write");

        DecodedJWT jwt = validator.validateTokenWithClaimIncludesAny(token, getHttpRequestInfo(), "scope", "admin", "write");

        assertThat(jwt).isNotNull();
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void validateTokenWithClaimIncludesAny_failure() throws Exception {
        String token = tokenWithScopes("read");

        validator.validateTokenWithClaimIncludesAny(token, getHttpRequestInfo(), "scope", "admin");
    }

    @Test
    public void decodeToken_success() throws Exception {
        DecodedJWT jwt = validator.decodeToken(validToken());

        assertThat(jwt.getSubject()).isEqualTo("user");
    }

    @Test(expected = VerifyAccessTokenException.class)
    public void decodeToken_failure() throws Exception {
        validator.decodeToken("invalid.jwt");
    }

    @Test
    public void getters_shouldReturnValues() {
        assertThat(validator.getAuthOptions()).isNotNull();
        assertThat(validator.getJwkProvider()).isNotNull();
    }

    private HttpRequestInfo getHttpRequestInfo() throws InvalidRequestException {
        return new HttpRequestInfo("GET", "https://api.example.com/resource", new HashMap<>());
    }

    private String validToken() {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withSubject("user")
                .withKeyId("kid")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.RSA256(publicKey, privateKey));
    }

    private String tokenWithScopes(String scopes) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withSubject("user")
                .withClaim("scope", scopes)
                .withKeyId("kid")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.RSA256(publicKey, privateKey));
    }

    private String tokenWithEmail(String email) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withSubject("user")
                .withClaim("email", email)
                .withKeyId("kid")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.RSA256(publicKey, privateKey));
    }
}
