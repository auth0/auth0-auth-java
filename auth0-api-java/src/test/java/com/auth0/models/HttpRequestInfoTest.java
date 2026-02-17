package com.auth0.models;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HttpRequestInfoTest {

    @Test
    public void testConstructorInitializesFieldsCorrectly() {
        Map<String, String> context = new HashMap<>();
        context.put("key", "value");

        HttpRequestInfo requestInfo = new HttpRequestInfo("get", "http://example.com", context);

        assertEquals("GET", requestInfo.getHttpMethod());
        assertEquals("http://example.com", requestInfo.getHttpUrl());
        assertEquals(Collections.singletonMap("key", "value"), requestInfo.getContext());
    }

    @Test
    public void testConstructorHandlesNullContext() {
        HttpRequestInfo requestInfo = new HttpRequestInfo("post", "http://example.com", null);

        assertEquals("POST", requestInfo.getHttpMethod());
        assertEquals("http://example.com", requestInfo.getHttpUrl());
        assertTrue(requestInfo.getContext().isEmpty());
    }

    @Test
    public void testGetHttpMethod() {
        HttpRequestInfo requestInfo = new HttpRequestInfo("put", "http://example.com", null);

        assertEquals("PUT", requestInfo.getHttpMethod());
    }

    @Test
    public void testGetHttpUrl() {
        HttpRequestInfo requestInfo = new HttpRequestInfo("delete", "http://example.com", null);

        assertEquals("http://example.com", requestInfo.getHttpUrl());
    }

    @Test
    public void testGetContextIsImmutable() {
        Map<String, String> context = new HashMap<>();
        context.put("key", "value");

        HttpRequestInfo requestInfo = new HttpRequestInfo("get", "http://example.com", context);

        Map<String, String> retrievedContext = requestInfo.getContext();
        try {
            retrievedContext.put("newKey", "newValue");
        } catch (UnsupportedOperationException e) {
            assertTrue(true);
        }
    }
}
