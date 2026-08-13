package com.auth0.telemetry;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable Auth0-Client telemetry payload.
 *
 * <p>Produces the Base64url-encoded value for the {@code Auth0-Client} header,
 * following the Auth0 SDK convention:
 * {@code {"name":..,"version":..,"env":{"java":..,"auth0-api-java":..}}}.
 *
 * <p>A wrapper library (e.g. the Spring Boot integration) reports itself as
 * {@code name}/{@code version} and passes the core library version so it lands
 * in {@code env} under {@link #CORE_LIBRARY_KEY}.
 */
public final class Telemetry {

    public static final String HEADER_NAME = "Auth0-Client";
    static final String CORE_LIBRARY_KEY = "auth0-api-java";

    private final String value;

    /**
     * @param name         the SDK name to report (required; a null name yields a
     *                     null header value that callers must skip)
     * @param version      the reporting SDK's version, or null to omit
     * @param coreVersion  the core {@code auth0-api-java} version to nest in
     *                     {@code env}, or null when the core library is itself
     *                     the reporter
     */
    public Telemetry(String name, String version, String coreVersion) {
        this.value = name == null ? null : encode(build(name, version, coreVersion));
    }

    /** @return the Base64url header value, or null if no name was provided */
    public String getValue() {
        return value;
    }

    private static Map<String, Object> build(String name, String version, String coreVersion) {
        Map<String, Object> env = new LinkedHashMap<>();
        if (coreVersion != null) {
            env.put(CORE_LIBRARY_KEY, coreVersion);
        }
        env.put("java", System.getProperty("java.specification.version", "unknown"));

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", name);
        if (version != null) {
            payload.put("version", version);
        }
        payload.put("env", env);
        return payload;
    }

    private static String encode(Map<String, Object> payload) {
        String json = toJson(payload);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("\"").append(escape(e.getKey())).append("\":");
            Object v = e.getValue();
            if (v instanceof Map) {
                sb.append(toJson((Map<String, Object>) v));
            } else {
                sb.append("\"").append(escape(String.valueOf(v))).append("\"");
            }
        }
        return sb.append("}").toString();
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
