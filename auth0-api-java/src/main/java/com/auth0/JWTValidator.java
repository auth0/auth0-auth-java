package com.auth0;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.MissingRequiredArgumentException;
import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.models.AuthOptions;
import com.auth0.models.OidcMetadata;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.models.HttpRequestInfo;
import com.auth0.models.RequestContext;
import com.auth0.OidcDiscoveryFetcher;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT Validator for Auth0 tokens
 * 
 * This class provides functionality to validate JWT tokens using RSA256
 * algorithm
 * and JWKS (JSON Web Key Set) for public key retrieval.
 */
class JWTValidator {

    static final String JWKS_CACHE_PREFIX = "jwks:";

    private final AuthOptions authOptions;
    private final JwkProvider jwkProvider;
    private final OidcDiscoveryFetcher discoveryFetcher;
    private final AuthCache<Object> cache;

    /**
     * Creates a JWT validator with domain and audience.
     * Uses the default in-memory LRU cache configured via {@link AuthOptions}.
     *
     * @param authOptions Authentication options containing domain and audience
     */
     JWTValidator(AuthOptions authOptions) {
        if (authOptions == null) {
            throw new IllegalArgumentException("AuthOptions cannot be null");
        }

        this.authOptions = authOptions;
        this.jwkProvider = authOptions.getDomain() != null
                ? new UrlJwkProvider(authOptions.getDomain())
                : null;
        this.cache = resolveCache(authOptions);
        this.discoveryFetcher = new OidcDiscoveryFetcher(this.cache);
    }

    /**
     * Creates a JWT validator with domain, audience, and a custom JwkProvider.
     *
     * @param authOptions Authentication options containing domain and audience
     * @param jwkProvider Custom JwkProvider for key retrieval
     */
    JWTValidator(AuthOptions authOptions, JwkProvider jwkProvider) {
        if (authOptions == null) {
            throw new IllegalArgumentException("AuthOptions cannot be null");
        }
        if (jwkProvider == null) {
            throw new IllegalArgumentException("JwkProvider cannot be null");
        }
        this.authOptions = authOptions;
        this.jwkProvider = jwkProvider;
        this.cache = resolveCache(authOptions);
        this.discoveryFetcher = new OidcDiscoveryFetcher(this.cache);
    }

    /**
     * Creates a JWT validator with all dependencies injectable (primarily for
     * testing).
     *
     * @param authOptions      Authentication options
     * @param jwkProvider      Custom JwkProvider for key retrieval
     * @param discoveryFetcher Custom OIDC discovery fetcher
     */
    JWTValidator(AuthOptions authOptions, JwkProvider jwkProvider, OidcDiscoveryFetcher discoveryFetcher) {
        if (authOptions == null) {
            throw new IllegalArgumentException("AuthOptions cannot be null");
        }
        this.authOptions = authOptions;
        this.jwkProvider = jwkProvider;
        this.cache = resolveCache(authOptions);
        this.discoveryFetcher = discoveryFetcher != null
                ? discoveryFetcher
                : new OidcDiscoveryFetcher(this.cache);
    }

    /**
     * Resolves the cache to use: custom from AuthOptions, or a new
     * InMemoryAuthCache.
     */
    private static AuthCache<Object> resolveCache(AuthOptions options) {
        if (options.getCache() != null) {
            return options.getCache();
        }
        return new InMemoryAuthCache<>(options.getCacheMaxEntries(), options.getCacheTtlSeconds());
    }

    /**
     * Validates a JWT token
     * 
     * @param token the JWT token to validate
     * @return the decoded and verified JWT
     * @throws BaseAuthException if validation fails
     */
     public DecodedJWT validateToken(String token, HttpRequestInfo httpRequestInfo) throws BaseAuthException {

        if (token == null || token.trim().isEmpty()) {
            throw new MissingRequiredArgumentException("access_token");
        }

        try {
            DecodedJWT unverifiedJwt = JWT.decode(token);
            String alg = unverifiedJwt.getAlgorithm();
            String tokenIss = unverifiedJwt.getIssuer();

            if (alg != null && alg.startsWith("HS")) {
                throw new VerifyAccessTokenException("Symmetric algorithms are not supported");
            }

            List<String> allowedDomains = resolveAllowedDomains(tokenIss, httpRequestInfo);

            // Normalize the token issuer and allowed domains for consistent comparison
            String normalizedIss = normalizeToUrl(tokenIss);
            if (!allowedDomains.contains(normalizedIss)) {
                throw new VerifyAccessTokenException(
                        String.format("Token issuer '%s' is not in the allowed list: %s"));
            }

            OidcMetadata discovery = performOidcDiscovery(tokenIss);

            if (!tokenIss.equals(discovery.getIssuer())) {
                throw new VerifyAccessTokenException("Discovery metadata issuer does not match token issuer");
            }

            JwkProvider dynamicJwkProvider = getOrCreateJwkProvider(discovery.getJwksUri());

            Jwk jwk = dynamicJwkProvider.get(unverifiedJwt.getKeyId());
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(tokenIss)
                    .withAudience(authOptions.getAudience())
                    .build();

            return verifier.verify(token);

        } catch (Exception e) {
            throw new VerifyAccessTokenException("signature verification failed", e);
        }
    }

    /**
     * Validates a JWT and ensures all required scopes are present.
     */
     DecodedJWT validateTokenWithRequiredScopes(String token, HttpRequestInfo httpRequestInfo, String... requiredScopes) throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkRequiredScopes(jwt, requiredScopes);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    /**
     * Validates a JWT and ensures it has *any* of the provided scopes.
     */
    public DecodedJWT validateTokenWithAnyScope(String token, HttpRequestInfo httpRequestInfo, String... scopes) throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkAnyScope(jwt, scopes);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    /**
     * Validates a JWT and ensures a claim equals the expected value.
     */
    public DecodedJWT validateTokenWithClaimEquals(String token, HttpRequestInfo httpRequestInfo, String claim, Object expected) throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkClaimEquals(jwt, claim, expected);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    /**
     * Validates a JWT and ensures a claim includes all expected values.
     */
    public DecodedJWT validateTokenWithClaimIncludes(String token, HttpRequestInfo httpRequestInfo, String claim, Object... expectedValues) throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkClaimIncludes(jwt, claim, expectedValues);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    public DecodedJWT validateTokenWithClaimIncludesAny(String token, HttpRequestInfo httpRequestInfo, String claim, Object... expectedValues) throws BaseAuthException {
        DecodedJWT jwt = validateToken(token, httpRequestInfo);
        try {
            ClaimValidator.checkClaimIncludesAny(jwt, claim, expectedValues);
            return jwt;
        } catch (Exception e) {
            throw wrapAsValidationException(e);
        }
    }

    public DecodedJWT decodeToken(String token) throws BaseAuthException {
        try {
            return JWT.decode(token);
        } catch (Exception e) {
            throw new VerifyAccessTokenException("Failed to decode JWT");
        }
    }

    private BaseAuthException wrapAsValidationException(Exception e) {
        if (e instanceof BaseAuthException)
            return (BaseAuthException) e;
        return new VerifyAccessTokenException("JWT claim validation failed");
    }

    public AuthOptions getAuthOptions() {
        return authOptions;
    }

    public JwkProvider getJwkProvider() {
        return jwkProvider;
    }

    /**
     * Performs OIDC Discovery for the given issuer URL
     * <p>
     * Fetches {@code GET https://<issuer>/.well-known/openid-configuration},
     * caches the response per domain, and returns the parsed metadata.
     * </p>
     *
     * @param issuerUrl the token's {@code iss} claim
     * @return the parsed OIDC discovery metadata
     * @throws VerifyAccessTokenException if the discovery fetch or parse fails
     */
    private OidcMetadata performOidcDiscovery(String issuerUrl) throws VerifyAccessTokenException {
        return discoveryFetcher.fetch(issuerUrl);
    }

    /**
     * Returns a cached {@link JwkProvider} for the given JWKS URI, creating one
     * if it does not yet exist
     * <p>
     * Uses the {@code jwks-rsa} library's {@link JwkProviderBuilder} which provides
     * built-in caching and rate-limiting. The provider cache is keyed by
     * {@code jwksUri} so each distinct JWKS endpoint gets its own cached provider.
     * </p>
     *
     * @param jwksUri the JWKS URI extracted from OIDC Discovery metadata
     * @return a JwkProvider that fetches keys from the given URI
     * @throws VerifyAccessTokenException if the JWKS URI is malformed
     */
    private JwkProvider getOrCreateJwkProvider(String jwksUri) throws VerifyAccessTokenException {
        String cacheKey = JWKS_CACHE_PREFIX + jwksUri;

        Object cached = cache.get(cacheKey);
        if (cached instanceof JwkProvider) {
            return (JwkProvider) cached;
        }

        try {
            JwkProvider provider = new JwkProviderBuilder(new URL(jwksUri)).build();
            cache.put(cacheKey, provider);
            return provider;
        } catch (MalformedURLException e) {
            throw new VerifyAccessTokenException(
                    String.format("Invalid JWKS URI '%s' from OIDC discovery", jwksUri), e);
        }
    }

    /**
     * Resolves the list of allowed issuers based on the configured strategy.
     *
     * <p>
     * Priority order:
     * <ol>
     * <li><b>Dynamic resolver</b> ({@code domainsResolver}) — highest priority</li>
     * <li><b>Static list</b> ({@code domains})</li>
     * <li><b>Legacy single domain</b> ({@code domain}) — backward compatibility
     * fallback</li>
     * </ol>
     *
     * @param tokenIss        the unverified {@code iss} claim from the decoded JWT
     * @param httpRequestInfo the HTTP request metadata (method, URL, headers)
     * @return a list of normalized issuer URLs (e.g.,
     *         {@code ["https://tenant.auth0.com/"]})
     */
    private List<String> resolveAllowedDomains(String tokenIss, HttpRequestInfo httpRequestInfo) {

        if (authOptions.getDomainsResolver() != null) {

            RequestContext context = new RequestContext.Builder()
                    .url(httpRequestInfo.getHttpUrl())
                    .headers(httpRequestInfo.getHeaders())
                    .tokenIssuer(tokenIss)
                    .build();

            // Call the user-provided resolver
            List<String> resolved = authOptions.getDomainsResolver().resolveDomains(context);

            return resolved != null
                    ? resolved.stream().map(this::normalizeToUrl).collect(Collectors.toList())
                    : Collections.emptyList();
        }

        if (authOptions.getDomains() != null && !authOptions.getDomains().isEmpty()) {
            return authOptions.getDomains().stream()
                    .map(this::normalizeToUrl)
                    .collect(Collectors.toList());
        }

        // If neither MCD option is used, fall back to the single 'domain' property.
        String domain = authOptions.getDomain();
        if (domain != null && !domain.isEmpty()) {
            return Collections.singletonList(normalizeToUrl(domain));
        }

        return Collections.emptyList();
    }

    /**
     * Normalizes a domain string into a full HTTPS URL with a trailing slash.
     * Ensures consistent comparison (e.g., {@code "tenant.auth0.com"} becomes
     * {@code "https://tenant.auth0.com/"}).
     *
     * @param domain the raw domain or URL string
     * @return the normalized URL, or {@code null} if input is {@code null}
     */
    private String normalizeToUrl(String domain) {
        if (domain == null)
            return null;

        String url = domain.trim();
        if (!url.toLowerCase().startsWith("http")) {
            url = "https://" + url;
        }
        return url.endsWith("/") ? url : url + "/";
    }
}
