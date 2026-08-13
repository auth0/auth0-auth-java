package com.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.models.AuthOptions;
import com.auth0.models.HttpRequestInfo;
import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end guard that the {@code Auth0-Client} telemetry header is attached to the
 * live JWKS key-fetch (the {@code getOrCreateJwkProvider} path validateToken actually
 * uses), mirroring the discovery-call coverage in {@link OidcDiscoveryFetcherTest}.
 *
 * <p>Uses an in-process {@link HttpServer} rather than mocking, because jwks-rsa wraps
 * the provider in caching/rate-limiting decorators whose header state is not publicly
 * observable — only the outgoing request proves the header survived.
 */
public class JWTValidatorTelemetryTest {

    private HttpServer server;
    private String baseUrl;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private final AtomicReference<String> jwksAuth0ClientHeader = new AtomicReference<>();
    private static final String KID = "test-kid";

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        publicKey = (RSAPublicKey) pair.getPublic();
        privateKey = (RSAPrivateKey) pair.getPrivate();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = server.getAddress().getPort();
        baseUrl = "http://127.0.0.1:" + port;

        server.createContext("/.well-known/openid-configuration", exchange -> {
            String body = String.format(
                    "{\"issuer\":\"%s/\",\"jwks_uri\":\"%s/.well-known/jwks.json\"}", baseUrl, baseUrl);
            respond(exchange, body);
        });

        server.createContext("/.well-known/jwks.json", exchange -> {
            jwksAuth0ClientHeader.set(exchange.getRequestHeaders().getFirst("Auth0-Client"));
            respond(exchange, jwksJson());
        });

        server.start();
    }

    @After
    public void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    public void jwksCall_shouldCarryTelemetryHeader() throws Exception {
        AuthOptions options = new AuthOptions.Builder()
                .domain(baseUrl)
                .audience("https://api.example.com")
                .build();

        JWTValidator validator = new JWTValidator(options);
        validator.validateToken(validToken(), httpRequestInfo());

        String expected = options.getTelemetry().getValue();
        assertThat(expected).isNotNull();
        assertThat(jwksAuth0ClientHeader.get()).isEqualTo(expected);
    }

    private String validToken() {
        return JWT.create()
                .withIssuer(baseUrl + "/")
                .withAudience("https://api.example.com")
                .withSubject("user")
                .withKeyId(KID)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.RSA256(publicKey, privateKey));
    }

    private HttpRequestInfo httpRequestInfo() throws Exception {
        return new HttpRequestInfo("GET", "https://api.example.com/resource", new HashMap<>());
    }

    private String jwksJson() {
        String n = base64Url(toUnsignedBytes(publicKey.getModulus()));
        String e = base64Url(toUnsignedBytes(publicKey.getPublicExponent()));
        return String.format(
                "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\"}]}",
                KID, n, e);
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) {
        try {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
