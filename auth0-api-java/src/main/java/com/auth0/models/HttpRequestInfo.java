package com.auth0.models;

import com.auth0.exception.InvalidRequestException;
import org.apache.http.util.Asserts;

import java.util.HashMap;
import java.util.Map;

public class HttpRequestInfo {
    private final String httpMethod;
    private final String httpUrl;
    private final Map<String, String> headers;

    public HttpRequestInfo(String httpMethod, String httpUrl, Map<String, String> headers) throws InvalidRequestException {
        Asserts.notNull(headers, "Headers map cannot be null");

        this.httpMethod = httpMethod != null ? httpMethod.toUpperCase() : null;
        this.httpUrl = httpUrl;
        this.headers = normalize(headers);
    }

    public HttpRequestInfo(Map<String, String> headers) throws InvalidRequestException {
        this(null, null, headers);
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getHttpUrl() {
        return httpUrl;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    private static Map<String, String> normalize(Map<String, String> headers) throws InvalidRequestException {
        Map<String, String> normalized = new HashMap<>(headers.size());

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey().toLowerCase();
            if (normalized.containsKey(key)) {
                throw new InvalidRequestException("Duplicate HTTP header detected");
            }
            normalized.put(key, entry.getValue());
        }
        return normalized;
    }
}
