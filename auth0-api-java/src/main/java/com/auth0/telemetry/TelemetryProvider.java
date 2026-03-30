package com.auth0.telemetry;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * Provides the Base64-encoded Auth0-Client telemetry header value.
 *
 * The payload is a JSON object: {"name":"springboot-api","version":"x.y.z","java":"17"}
 */
public final class TelemetryProvider {

    private static final String PROPERTIES_FILE = "auth0-client-info.properties";
    private static final String UNKNOWN = "unknown";

    private static volatile String cachedHeaderValue;

    private TelemetryProvider() {
    }

    /**
     * Returns the Base64url-encoded telemetry header value.
     *
     * @return the Auth0-Client header value, or null if it cannot be built
     */
    public static String getHeaderValue() {
        if (cachedHeaderValue != null) {
            return cachedHeaderValue;
        }
        synchronized (TelemetryProvider.class) {
            if (cachedHeaderValue != null) {
                return cachedHeaderValue;
            }
            cachedHeaderValue = buildHeaderValue();
            return cachedHeaderValue;
        }
    }

    private static String buildHeaderValue() {
        String name = UNKNOWN;
        String version = UNKNOWN;

        try (InputStream is = TelemetryProvider.class.getClassLoader()
                .getResourceAsStream(PROPERTIES_FILE)) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                name = props.getProperty("name", UNKNOWN);
                version = props.getProperty("version", UNKNOWN);
            }
        } catch (IOException ignored) {
            // Fall through with defaults
        }

        String javaVersion = System.getProperty("java.version", UNKNOWN);

        String json = "{\"name\":\"" + name + "\",\"version\":\"" + version + "\",\"java\":\"" + javaVersion + "\"}";

        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
