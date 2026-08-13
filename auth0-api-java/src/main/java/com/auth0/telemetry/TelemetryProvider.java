package com.auth0.telemetry;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Reads the core library's name and version from the build-filtered
 * {@code auth0-client-info.properties} resource and builds the default
 * {@link Telemetry} identity for {@code auth0-api-java}.
 *
 * <p>Wrappers construct their own {@link Telemetry} instead of using this.
 */
public final class TelemetryProvider {

    private static final String PROPERTIES_FILE = "auth0-client-info.properties";
    private static final String UNKNOWN = "unknown";

    private static volatile Telemetry cached;

    private TelemetryProvider() {
    }

    /** @return the core {@code auth0-api-java} telemetry identity (no nested env core version) */
    public static Telemetry getDefault() {
        if (cached != null) {
            return cached;
        }
        synchronized (TelemetryProvider.class) {
            if (cached == null) {
                cached = new Telemetry(readName(), readVersion(), null);
            }
            return cached;
        }
    }

    /** @return the core library version, or {@code "unknown"} if unavailable */
    public static String coreVersion() {
        return readVersion();
    }

    private static String readName() {
        return read("name");
    }

    private static String readVersion() {
        return read("version");
    }

    private static String read(String key) {
        try (InputStream is = TelemetryProvider.class.getClassLoader()
                .getResourceAsStream(PROPERTIES_FILE)) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                return props.getProperty(key, UNKNOWN);
            }
        } catch (IOException ignored) {
            // fall through
        }
        return UNKNOWN;
    }
}
