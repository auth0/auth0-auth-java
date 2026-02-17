package com.auth0;

import com.auth0.enums.AuthScheme;
import com.auth0.exception.*;
import com.auth0.models.AuthToken;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenExtractorTest {

    private final TokenExtractor extractor = new TokenExtractor();

    @Test
    public void getScheme_shouldReturnLowercaseScheme() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "Bearer abc");

        String scheme = extractor.getScheme(headers);

        assertThat(scheme).isEqualTo("bearer");
    }

    @Test(expected = MissingAuthorizationException.class)
    public void getScheme_shouldFailWhenHeaderMissing() throws Exception {
        extractor.getScheme(new HashMap<>());
    }

    @Test
    public void extractBearer_shouldReturnBearerToken() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "Bearer token");

        AuthToken token = extractor.extractBearer(headers);

        assertThat(token.getAccessToken()).isEqualTo("token");
        assertThat(token.getProof()).isNull();
        assertThat(token.getScheme()).isEqualTo(AuthScheme.BEARER);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void extractBearer_shouldRejectNonBearerScheme() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "DPoP token");

        extractor.extractBearer(headers);
    }

    @Test
    public void extractDPoPProofAndDPoPToken_shouldReturnDpopToken() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "DPoP token");
        headers.put(AuthConstants.DPOP_HEADER, "proof");

        AuthToken token = extractor.extractDPoPProofAndDPoPToken(headers);

        assertThat(token.getAccessToken()).isEqualTo("token");
        assertThat(token.getProof()).isEqualTo("proof");
        assertThat(token.getScheme()).isEqualTo(AuthScheme.DPOP);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void extractDPoPProofAndDPoPToken_shouldRejectBearerScheme() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "Bearer token");
        headers.put(AuthConstants.DPOP_HEADER, "proof");

        extractor.extractDPoPProofAndDPoPToken(headers);
    }

    @Test(expected = InvalidDpopProofException.class)
    public void extractDPoPProofAndDPoPToken_shouldRejectMultipleProofs() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "DPoP token");
        headers.put(AuthConstants.DPOP_HEADER, "p1,p2");

        extractor.extractDPoPProofAndDPoPToken(headers);
    }

    @Test(expected = InvalidAuthSchemeException.class)
    public void extractDPoPProofAndDPoPToken_shouldRejectMissingProof() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "DPoP token");

        extractor.extractDPoPProofAndDPoPToken(headers);
    }

    @Test(expected = MissingAuthorizationException.class)
    public void splitAuthHeader_shouldRejectEmptyHeader() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, " ");

        extractor.extractBearer(headers);
    }

    @Test(expected = MissingAuthorizationException.class)
    public void splitAuthHeader_shouldRejectMalformedHeader() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "Bearer");

        extractor.extractBearer(headers);
    }

    @Test(expected = MissingAuthorizationException.class)
    public void splitAuthHeader_shouldRejectTokenWithSpaces() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthConstants.AUTHORIZATION_HEADER, "Bearer abc def");

        extractor.extractBearer(headers);
    }
}
