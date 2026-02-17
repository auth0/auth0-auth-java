package com.auth0.models;

import java.util.Collections;
import java.util.Map;

public class HttpRequestInfo {
    private final String httpMethod;
    private final String httpUrl;
    private final Map<String, String> context;

    public HttpRequestInfo(String httpMethod, String httpUrl, Map<String, String> context) {
        this.httpMethod = httpMethod.toUpperCase();
        this.httpUrl = httpUrl;
        this.context = context != null ? Collections.unmodifiableMap(context) : Collections.emptyMap();
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getHttpUrl() {
        return httpUrl;
    }

    public Map<String, String> getContext() {
        return context;
    }
}
