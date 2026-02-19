package com.auth0.models;

import com.auth0.exception.BaseAuthException;
import com.auth0.exception.InvalidRequestException;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HttpRequestInfoTest {

    @Test
    public void testConstructorInitializesFieldsCorrectly() throws InvalidRequestException {
        Map<String, String> headers = new HashMap<>();
        headers.put("key", "value");

        HttpRequestInfo requestInfo = new HttpRequestInfo("get", "http://example.com", headers);

        assertEquals("GET", requestInfo.getHttpMethod());
        assertEquals("http://example.com", requestInfo.getHttpUrl());
        assertEquals(Collections.singletonMap("key", "value"), requestInfo.getHeaders());
    }


    @Test
    public void testGetHttpMethod() throws InvalidRequestException {
        HttpRequestInfo requestInfo = new HttpRequestInfo("put", "http://example.com", new HashMap<>());

        assertEquals("PUT", requestInfo.getHttpMethod());
    }

    @Test
    public void testGetHttpUrl() throws InvalidRequestException {
        HttpRequestInfo requestInfo = new HttpRequestInfo("delete", "http://example.com", new HashMap<>());

        assertEquals("http://example.com", requestInfo.getHttpUrl());
    }

    @Test
    public void testGetContextIsImmutable() throws InvalidRequestException {
        Map<String, String> headers = new HashMap<>();
        headers.put("key", "value");

        HttpRequestInfo requestInfo = new HttpRequestInfo("get", "http://example.com", headers);

        Map<String, String> retrievedHeaders = requestInfo.getHeaders();
        try {
            retrievedHeaders.put("newKey", "newValue");
        } catch (UnsupportedOperationException e) {
            assertTrue(true);
        }
    }

    @Test(expected = InvalidRequestException.class)
    public void normalize_shouldThrowOnDuplicateHeaders() throws BaseAuthException {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "a");
        headers.put("authorization", "b");

        HttpRequestInfo requestInfo = new HttpRequestInfo("get", "http://example.com", headers);

    }
}
