package com.auth0.models;

import com.auth0.enums.DPoPMode;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class AuthOptionsTest {

    @Test
    public void testBuilderSetsFieldsCorrectly() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .dpopMode(DPoPMode.REQUIRED)
                .dpopIatOffsetSeconds(600)
                .dpopIatLeewaySeconds(60)
                .build();

        assertEquals("example.com", options.getDomain());
        assertEquals("api://default", options.getAudience());
        assertEquals(DPoPMode.REQUIRED, options.getDpopMode());
        assertEquals(600, options.getDpopIatOffsetSeconds());
        assertEquals(60, options.getDpopIatLeewaySeconds());
    }

    @Test
    public void testBuilderThrowsExceptionForNegativeIatOffset() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                new AuthOptions.Builder().dpopIatOffsetSeconds(-1)
        );
        assertEquals("dpopIatOffsetSeconds must not be negative", exception.getMessage());
    }

    @Test
    public void testBuilderThrowsExceptionForNegativeIatLeeway() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                new AuthOptions.Builder().dpopIatLeewaySeconds(-1)
        );
        assertEquals("dpopIatLeewaySeconds must not be negative", exception.getMessage());
    }

    @Test
    public void testBuildThrowsExceptionForNullDomain() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                new AuthOptions.Builder()
                        .audience("api://default")
                        .build()
        );
        assertEquals("Domain must not be null or empty", exception.getMessage());
    }

    @Test
    public void testBuildThrowsExceptionForNullAudience() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                new AuthOptions.Builder()
                        .domain("example.com")
                        .build()
        );
        assertEquals("Audience must not be null or empty", exception.getMessage());
    }

    @Test
    public void testDefaultValuesInBuilder() {
        AuthOptions options = new AuthOptions.Builder()
                .domain("example.com")
                .audience("api://default")
                .build();

        assertEquals(DPoPMode.ALLOWED, options.getDpopMode());
        assertEquals(300, options.getDpopIatOffsetSeconds());
        assertEquals(30, options.getDpopIatLeewaySeconds());
    }
}