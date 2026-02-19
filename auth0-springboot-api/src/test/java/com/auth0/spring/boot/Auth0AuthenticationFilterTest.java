package com.auth0.spring.boot;

import com.auth0.AuthClient;
import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.exception.MissingAuthorizationException;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test cases for Auth0AuthenticationFilter
 */
@ExtendWith(MockitoExtension.class)
class Auth0AuthenticationFilterTest {

    @Mock
    private Auth0Properties auth0Properties;

    @Mock
    private AuthClient authClient;

    @Mock
    private FilterChain filterChain;

    private Auth0AuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        filter = new Auth0AuthenticationFilter(authClient, auth0Properties);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("Should return empty map when request has no headers")
    void extractHeaders_shouldReturnEmptyMap_whenNoHeadersPresent() throws MissingAuthorizationException {
        Map<String, String> headers = filter.extractHeaders(request);

        assertNotNull(headers);
        assertTrue(headers.isEmpty());
    }

    @Test
    @DisplayName("Should extract single header with normalized lowercase name")
    void extractHeaders_shouldExtractSingleHeader_withLowercaseName() throws MissingAuthorizationException {
        request.addHeader("Authorization", "Bearer token123");

        Map<String, String> headers = filter.extractHeaders(request);

        assertEquals(1, headers.size());
        assertEquals("Bearer token123", headers.get("authorization"));
    }

    @Test
    @DisplayName("Should extract multiple headers with all names normalized to lowercase")
    void extractHeaders_shouldExtractMultipleHeaders_withNormalizedNames() throws MissingAuthorizationException {
        String bearerToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyJ9.signature";
        String dpopProof = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiIxMjM0NSJ9.proof";

        request.addHeader("AuThOrIzAtIoN", bearerToken);
        request.addHeader("Content-Type", "application/json");
        request.addHeader("DPoP", dpopProof);

        Map<String, String> headers = filter.extractHeaders(request);

        assertEquals(3, headers.size());
        assertEquals(bearerToken, headers.get("authorization"));
        assertEquals("application/json", headers.get("content-type"));
        assertEquals(dpopProof, headers.get("dpop"));
    }

    @Test
    @DisplayName("Should fail when multiple authorization headers are present")
    void extractHeaders_shouldThrowExceptionWhenMultipleAuthorizationHeadersArePresent(){

        when(auth0Properties.getDpopMode()).thenReturn(DPoPMode.REQUIRED);
        String dpopToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyJ9.signature";
        String dpopProof = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiIxMjM0NSJ9.proof";

        request.addHeader("authorization", dpopToken);
        request.addHeader("Content-Type", "application/json");
        request.addHeader("DPoP", dpopProof);
        request.addHeader("Authorization", dpopToken);

        MissingAuthorizationException ex = assertThrows(
                MissingAuthorizationException.class,
                () -> filter.extractHeaders(request)
        );

        assertEquals(400, ex.getStatusCode());
    }

    @Test
    @DisplayName("Should return empty map when header enumeration is null")
    void extractHeaders_shouldReturnEmptyMap_whenHeaderEnumerationIsNull() throws MissingAuthorizationException {
        MockHttpServletRequest nullHeaderRequest = new MockHttpServletRequest() {
            @Override
            public Enumeration<String> getHeaderNames() {
                return null;
            }
        };

        Map<String, String> headers = filter.extractHeaders(nullHeaderRequest);

        assertNotNull(headers);
        assertTrue(headers.isEmpty());
    }

    @Test
    @DisplayName("Should build HTTP URL with default port 80")
    void buildHtu_shouldBuildHttpUrl_withDefaultPort() {
        request.setScheme("http");
        request.setServerName("example.com");
        request.setServerPort(80);
        request.setRequestURI("/api/users");

        String htu = Auth0AuthenticationFilter.buildHtu(request);

        assertEquals("http://example.com/api/users", htu);
    }

    @Test
    @DisplayName("Should build HTTPS URL with default port 443")
    void buildHtu_shouldBuildHttpsUrl_withDefaultPort() {
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/v2/resource");

        String htu = Auth0AuthenticationFilter.buildHtu(request);

        assertEquals("https://api.example.com/v2/resource", htu);
    }

    @Test
    @DisplayName("Should build HTTP URL with non-default port")
    void buildHtu_shouldBuildHttpUrl_withNonDefaultPort() {
        request.setScheme("HtTp");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/test");

        String htu = Auth0AuthenticationFilter.buildHtu(request);

        assertEquals("http://localhost:8080/test", htu);
    }

    @Test
    @DisplayName("Should build HTTPS URL with non-default port")
    void buildHtu_shouldBuildHttpsUrl_withNonDefaultPort() {
        request.setScheme("https");
        request.setServerName("secure.example.com");
        request.setServerPort(8443);
        request.setRequestURI("/api/data");

        String htu = Auth0AuthenticationFilter.buildHtu(request);

        assertEquals("https://secure.example.com:8443/api/data", htu);
    }

    @Test
    @DisplayName("Should normalize scheme and host to lowercase")
    void buildHtu_shouldNormalizeSchemeAndHost_toLowerCase() {
        request.setScheme("HTTPS");
        request.setServerName("API.EXAMPLE.COM");
        request.setServerPort(443);
        request.setRequestURI("/Resource");

        String htu = Auth0AuthenticationFilter.buildHtu(request);

        assertEquals("https://api.example.com/Resource", htu);
    }

    @Test
    @DisplayName("Should create HttpRequestInfo with GET method and built HTU")
    void extractRequestInfo_shouldCreateHttpRequestInfo_withGetMethod() throws BaseAuthException {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");

        Map<String, String> headers = new HashMap<>();

        HttpRequestInfo requestInfo = filter.extractRequestInfo(request, headers);

        assertNotNull(requestInfo);
        assertEquals("GET", requestInfo.getHttpMethod());
        assertEquals("https://api.example.com/api/users", requestInfo.getHttpUrl());
    }

    @Test
    @DisplayName("Should authenticate successfully with valid Bearer token and set security context")
    void doFilterInternal_shouldAuthenticateSuccessfully_withValidBearerToken() throws Exception {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");
        request.addHeader("Authorization", "Bearer valid_token");

        AuthenticationContext mockContext = org.mockito.Mockito.mock(AuthenticationContext.class);
        when(authClient.verifyRequest(
                any(HttpRequestInfo.class)
        )).thenReturn(mockContext);

        filter.doFilterInternal(request, response, filterChain);

        verify(authClient).verifyRequest(
                any(HttpRequestInfo.class)
        );
        verify(filterChain).doFilter(request, response);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof Auth0AuthenticationToken);
    }

    @Test
    @DisplayName("Should authenticate successfully with valid DPoP token and proof")
    void doFilterInternal_shouldAuthenticateSuccessfully_withValidDpopToken() throws Exception {
        request.setMethod("POST");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/resource");
        request.addHeader("Authorization", "DPoP dpop_token");
        request.addHeader("DPoP", "dpop_proof_jwt");

        AuthenticationContext mockContext = org.mockito.Mockito.mock(AuthenticationContext.class);
        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenReturn(mockContext);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Should handle missing authorization header by returning 200 status")
    void doFilterInternal_shouldReturn200_whenAuthorizationHeaderMissing() throws Exception {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(200, response.getStatus());
        verify(filterChain).doFilter(request, response);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Should handle invalid token by returning 401 status and clearing context")
    void doFilterInternal_shouldReturn401AndClearContext_withInvalidToken() throws Exception {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");
        request.addHeader("Authorization", "Bearer invalid_token");

        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenThrow(new com.auth0.exception.VerifyAccessTokenException("Invalid JWT signature"));

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verify(filterChain, org.mockito.Mockito.never()).doFilter(request, response);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Should handle insufficient scope by returning 403 status")
    void doFilterInternal_shouldReturn403_withInsufficientScope() throws Exception {
        request.setMethod("POST");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/admin");
        request.addHeader("Authorization", "Bearer valid_token");

        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenThrow(new com.auth0.exception.InsufficientScopeException("Insufficient scope"));

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(403, response.getStatus());
        verify(filterChain, org.mockito.Mockito.never()).doFilter(request, response);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Should add WWW-Authenticate header when present in exception")
    void doFilterInternal_shouldAddWwwAuthenticateHeader_whenPresentInException() throws Exception {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");
        request.addHeader("Authorization", "Bearer expired_token");

        Map<String, String> exceptionHeaders = new java.util.HashMap<>();
        exceptionHeaders.put("WWW-Authenticate", "Bearer realm=\"api\", error=\"invalid_token\"");

        // Simulating an exception that would be thrown by the authClient
        com.auth0.exception.VerifyAccessTokenException exception =
                new com.auth0.exception.VerifyAccessTokenException("Token expired");
        exception.addHeader("WWW-Authenticate", "Bearer realm=\"api\", error=\"invalid_token\"");

        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenThrow(exception);

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer realm=\"api\", error=\"invalid_token\"",
                response.getHeader("WWW-Authenticate"));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Should not add WWW-Authenticate header when not present in exception")
    void doFilterInternal_shouldNotAddWwwAuthenticateHeader_whenNotPresentInException() throws Exception {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");
        request.addHeader("Authorization", "Bearer malformed_token");

        com.auth0.exception.VerifyAccessTokenException exception =
                new com.auth0.exception.VerifyAccessTokenException("Malformed token");

        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenThrow(exception);

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Should set authentication details from request")
    void doFilterInternal_shouldSetAuthenticationDetails_fromRequest() throws Exception {
        request.setMethod("GET");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/users");
        request.setRemoteAddr("192.168.1.100");
        request.addHeader("Authorization", "Bearer valid_token");

        AuthenticationContext mockContext = org.mockito.Mockito.mock(AuthenticationContext.class);
        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenReturn(mockContext);

        filter.doFilterInternal(request, response, filterChain);

        Auth0AuthenticationToken auth =
                (Auth0AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth.getDetails());
    }

    @Test
    @DisplayName("Should handle DPoP validation exception and return appropriate status")
    void doFilterInternal_shouldHandleDpopValidationException_withProperStatus() throws Exception {
        request.setMethod("POST");
        request.setScheme("https");
        request.setServerName("api.example.com");
        request.setServerPort(443);
        request.setRequestURI("/api/resource");
        request.addHeader("Authorization", "DPoP dpop_token");
        request.addHeader("DPoP", "invalid_proof");

        Map<String, String> exceptionHeaders = new java.util.HashMap<>();
        exceptionHeaders.put("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");

        // Simulating an exception that would be thrown by the authClient
        com.auth0.exception.InvalidDpopProofException exception =
                new com.auth0.exception.InvalidDpopProofException("Invalid DPoP proof");
        exception.addHeader("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");
        
        when(authClient.verifyRequest(any(HttpRequestInfo.class))).thenThrow(exception);

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(400, response.getStatus());
        assertEquals("DPoP error=\"invalid_dpop_proof\"", response.getHeader("WWW-Authenticate"));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}

