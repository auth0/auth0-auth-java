package com.auth0.models;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcMetadataTest {

    @Test
    public void shouldStoreIssuerAndJwksUri() {
        OidcMetadata metadata = new OidcMetadata(
                "https://tenant.auth0.com/",
                "https://tenant.auth0.com/.well-known/jwks.json");

        assertThat(metadata.getIssuer()).isEqualTo("https://tenant.auth0.com/");
        assertThat(metadata.getJwksUri()).isEqualTo("https://tenant.auth0.com/.well-known/jwks.json");
    }

    @Test
    public void shouldAllowNullValues() {
        OidcMetadata metadata = new OidcMetadata(null, null);

        assertThat(metadata.getIssuer()).isNull();
        assertThat(metadata.getJwksUri()).isNull();
    }
}
