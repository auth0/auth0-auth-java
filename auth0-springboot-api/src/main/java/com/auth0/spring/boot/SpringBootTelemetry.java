package com.auth0.spring.boot;

import com.auth0.telemetry.Telemetry;
import com.auth0.telemetry.TelemetryProvider;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Builds the {@link Telemetry} identity for {@code auth0-springboot-api}, reporting the wrapper as
 * the top-level SDK and nesting the core {@code auth0-api-java} version under {@code env}.
 */
final class SpringBootTelemetry {

  private static final String PROPERTIES_FILE = "auth0-springboot-client-info.properties";
  private static final String NAME = "auth0-springboot-api";
  private static final String UNKNOWN = "unknown";

  private SpringBootTelemetry() {}

  static Telemetry get() {
    return new Telemetry(NAME, readVersion(), TelemetryProvider.coreVersion());
  }

  private static String readVersion() {
    try (InputStream is =
        SpringBootTelemetry.class.getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
      if (is != null) {
        Properties props = new Properties();
        props.load(is);
        return props.getProperty("version", UNKNOWN);
      }
    } catch (IOException ignored) {
      // fall through
    }
    return UNKNOWN;
  }
}
