package com.auth0;

import com.auth0.exception.VerifyAccessTokenException;
import com.auth0.models.OidcMetadata;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicStatusLine;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OidcDiscoveryFetcherTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    private OidcDiscoveryFetcher fetcher;
    private InMemoryAuthCache<Object> cache;

    private static final String ISSUER = "https://tenant.auth0.com/";
    private static final String JWKS_URI = "https://tenant.auth0.com/.well-known/jwks.json";

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        cache = new InMemoryAuthCache<>();
        fetcher = new OidcDiscoveryFetcher(cache, httpClient);
    }

    @Test
    public void fetch_shouldReturnMetadataOnSuccess() throws Exception {
        String discoveryJson = String.format(
                "{\"issuer\":\"%s\",\"jwks_uri\":\"%s\"}", ISSUER, JWKS_URI);
        mockSuccessResponse(discoveryJson);

        OidcMetadata metadata = fetcher.fetch(ISSUER);

        assertThat(metadata.getIssuer()).isEqualTo(ISSUER);
        assertThat(metadata.getJwksUri()).isEqualTo(JWKS_URI);
    }

    @Test
    public void fetch_shouldCacheResultPerDomain() throws Exception {
        String discoveryJson = String.format(
                "{\"issuer\":\"%s\",\"jwks_uri\":\"%s\"}", ISSUER, JWKS_URI);
        mockSuccessResponse(discoveryJson);

        OidcMetadata first = fetcher.fetch(ISSUER);
        OidcMetadata second = fetcher.fetch(ISSUER);

        assertThat(first.getIssuer()).isEqualTo(second.getIssuer());
        assertThat(first.getJwksUri()).isEqualTo(second.getJwksUri());
        verify(httpClient, times(1)).execute(any());
    }

    @Test
    public void fetch_shouldUsePrefixedCacheKey() throws Exception {
        String discoveryJson = String.format(
                "{\"issuer\":\"%s\",\"jwks_uri\":\"%s\"}", ISSUER, JWKS_URI);
        mockSuccessResponse(discoveryJson);

        fetcher.fetch(ISSUER);

        // Verify the cache key uses the "discovery:" prefix
        assertThat(cache.get(OidcDiscoveryFetcher.CACHE_PREFIX + ISSUER)).isNotNull();
        assertThat(cache.get(OidcDiscoveryFetcher.CACHE_PREFIX + ISSUER)).isInstanceOf(OidcMetadata.class);
    }

    @Test
    public void fetch_shouldNormalizeIssuerKeyWithTrailingSlash() throws Exception {
        String issuerWithoutSlash = "https://tenant.auth0.com";
        String discoveryJson = String.format(
                "{\"issuer\":\"%s\",\"jwks_uri\":\"%s\"}", ISSUER, JWKS_URI);
        mockSuccessResponse(discoveryJson);

        OidcMetadata metadata = fetcher.fetch(issuerWithoutSlash);

        assertThat(metadata.getIssuer()).isEqualTo(ISSUER);
        assertThat(cache.get(OidcDiscoveryFetcher.CACHE_PREFIX + ISSUER)).isNotNull();
    }

    @Test
    public void fetch_shouldThrowOnNon200Response() throws Exception {
        when(httpResponse.getStatusLine())
                .thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 404, "Not Found"));
        when(httpResponse.getEntity()).thenReturn(new StringEntity(""));
        when(httpClient.execute(any())).thenReturn(httpResponse);

        assertThatThrownBy(() -> fetcher.fetch(ISSUER))
                .isInstanceOf(VerifyAccessTokenException.class)
                .hasMessageContaining("OIDC discovery failed")
                .hasMessageContaining("HTTP 404");
    }

    @Test
    public void fetch_shouldThrowWhenIssuerFieldMissing() throws Exception {
        String json = String.format("{\"jwks_uri\":\"%s\"}", JWKS_URI);
        mockSuccessResponse(json);

        assertThatThrownBy(() -> fetcher.fetch(ISSUER))
                .isInstanceOf(VerifyAccessTokenException.class)
                .hasMessageContaining("missing required field 'issuer'");
    }

    @Test
    public void fetch_shouldThrowWhenJwksUriFieldMissing() throws Exception {
        String json = String.format("{\"issuer\":\"%s\"}", ISSUER);
        mockSuccessResponse(json);

        assertThatThrownBy(() -> fetcher.fetch(ISSUER))
                .isInstanceOf(VerifyAccessTokenException.class)
                .hasMessageContaining("missing required field 'jwks_uri'");
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_shouldRejectNullCache() {
        new OidcDiscoveryFetcher(null, httpClient);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_shouldRejectNullHttpClient() {
        new OidcDiscoveryFetcher(cache, null);
    }

    @Test
    public void clearCache_shouldEmptyTheCache() throws Exception {
        String discoveryJson = String.format(
                "{\"issuer\":\"%s\",\"jwks_uri\":\"%s\"}", ISSUER, JWKS_URI);
        mockSuccessResponse(discoveryJson);

        fetcher.fetch(ISSUER);
        assertThat(fetcher.cacheSize()).isGreaterThan(0);

        fetcher.clearCache();
        assertThat(fetcher.cacheSize()).isEqualTo(0);
    }

    private void mockSuccessResponse(String body) throws Exception {
        when(httpResponse.getStatusLine())
                .thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 200, "OK"));
        when(httpResponse.getEntity()).thenReturn(new StringEntity(body));
        when(httpClient.execute(any())).thenReturn(httpResponse);
    }
}
