# Copilot Instructions for Auth0 Java SDK

## Architecture Overview

Multi-module Gradle project implementing OAuth2/JWT authentication with DPoP support:

- `auth0-api-java`: Java 8 compatible core library (JWT validation, JWKS, DPoP proofs)
- `auth0-springboot-api`: Java 17 Spring Boot auto-configuration and filters
- `auth0-springboot-api-playground`: Working example application with security integration

**Key Design**: Strategy pattern for authentication modes, factory-based client creation, comprehensive JWT validation with Auth0 JWKS integration.

## Core Authentication Pattern

**Main Entry Point**: `AuthClient.from(AuthOptions)` → creates orchestrator with strategy pattern:

```java
// Factory method selects authentication strategy based on DPoP mode
AuthClient client = AuthClient.from(
    new AuthOptions.Builder()
        .domain("tenant.auth0.com")
        .audience("https://api.example.com")
        .dpopMode(DPoPMode.ALLOWED)  // DISABLED, ALLOWED (default), REQUIRED
        .dpopIatOffsetSeconds(300)   // DPoP proof time window
        .dpopIatLeewaySeconds(60)    // DPoP proof time leeway
        .build()
);

// Single verification method for all authentication modes
AuthenticationContext context = client.verifyRequest(headers, httpRequestInfo);
```

**Three Authentication Strategies** extending `AbstractAuthentication`:

- `DisabledDPoPAuthentication`: Bearer tokens only
- `AllowedDPoPAuthentication`: Bearer OR DPoP tokens (auto-detects scheme)
- `RequiredDPoPAuthentication`: DPoP tokens only

**Strategy Selection** happens in `AuthClient` constructor based on `dpopMode`.

## JWT Validation & Claims Patterns

**Always use `JWTValidator` convenience methods** - they handle JWKS fetching and validation:

```java
// Scope validation
DecodedJWT jwt = validator.validateTokenWithRequiredScopes(token, "read:users", "write:users");
DecodedJWT jwt = validator.validateTokenWithAnyScope(token, "admin", "user");

// Claim validation
DecodedJWT jwt = validator.validateTokenWithClaimEquals(token, "role", "admin");
DecodedJWT jwt = validator.validateTokenWithClaimIncludes(token, "permissions", "create");

// Manual validation for complex scenarios
DecodedJWT jwt = validator.validateToken(token);
ClaimValidators.checkRequiredScopes(jwt, "admin");
```

**Key Classes**:

- `JWTValidator`: Core JWT validation with JWKS integration (uses Auth0's `jwks-rsa` library)
- `ClaimValidator`: Manual claim validation helpers
- `DPoPProofValidator`: ES256 signature and proof claim validation
- `TokenExtractor`: Extracts Bearer/DPoP tokens from Authorization headers

## Build & Test Workflows

**Module-specific commands** (root gradle builds are disabled):

```bash
# Core library
./gradlew :auth0-api-java:build
./gradlew :auth0-api-java:test

# Spring Boot integration
./gradlew :auth0-springboot-api:build
./gradlew :auth0-springboot-api:test

# Playground/example
./gradlew :auth0-springboot-api-playground:bootRun
```

**Test Patterns**:

- **JUnit versions**: JUnit 4 (auth0-api-java), JUnit 5 (Spring Boot modules)
- **JWT testing**: Mock `JwkProvider`, generate RSA keypairs, use real JWT/JWKS validation
- **DPoP testing**: Generate ES256 keypairs, create valid/invalid DPoP proofs
- **AssertJ**: Preferred assertion library (`assertThat()`, `assertThatThrownBy()`)

**JAR artifacts**: All modules auto-generate sources/javadoc JARs via `withSourcesJar()`/`withJavadocJar()`

## Spring Boot Integration

**Auto-Configuration**: Add dependency, configure properties, inject beans:

```yaml
# application.yml
auth0:
  domain: "dev-tenant.us.auth0.com"
  audience: "https://api.example.com/v2/"
  dpopMode: ALLOWED
  dpopIatOffsetSeconds: 300
  dpopIatLeewaySeconds: 60
```

```java
// Auto-configured beans available for injection
@Autowired private AuthClient authClient;
@Autowired private AuthOptions authOptions;
@Autowired private Auth0AuthenticationFilter authFilter;
```

**Security Configuration Pattern**:

```java
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, Auth0AuthenticationFilter authFilter) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                   .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
                   .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/api/protected").authenticated()
                       .anyRequest().permitAll())
                   .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                   .build();
    }
}
```

**Classes**: `Auth0AutoConfiguration`, `Auth0Properties`, `Auth0AuthenticationFilter`, `Auth0AuthenticationToken`

## DPoP (Demonstration of Proof-of-Possession) Patterns

**DPoP Mode Behavior**:

- `DISABLED`: Only Bearer tokens accepted
- `ALLOWED` (default): Bearer OR DPoP tokens accepted (auto-detects Authorization scheme)
- `REQUIRED`: Only DPoP tokens accepted

**Critical Validation Rules**:

```java
// ALLOWED mode: Bearer token + DPoP proof header = invalid_request
if (scheme.equals(BEARER) && dpopProofPresent) {
    throw new JWTValidationException("Bearer scheme cannot include DPoP proof header");
}

// DPoP bound token (cnf.jkt claim) with Bearer scheme = invalid_token
if (tokenIsDPoPBound && scheme.equals(BEARER)) {
    throw new JWTValidationException("DPoP bound token requires DPoP scheme");
}
```

**DPoP Proof Validation**:

- **Header**: `typ: "dpop+jwt"`, `alg: "ES256"`, embedded JWK required
- **Claims**: `htm` (HTTP method), `htu` (HTTP URI), `iat` (issued at with time windows)
- **Token Binding**: Access token's `cnf.jkt` must match DPoP proof JWK thumbprint (RFC 7638)

**WWW-Authenticate Challenges**:

- ALLOWED/DISABLED: `Bearer realm=api; DPoP algs=ES256`
- REQUIRED: `DPoP algs=ES256`
- DPoP errors: `DPoP error=invalid_dpop_proof; error_description="..."`

## Package Structure & Key Classes

**Core (`auth0-api-java/com/auth0/`)**:

- Root: `AuthClient` (main entry), `AbstractAuthentication` (strategy base), authentication strategies
- `validators/`: `JWTValidator`, `DPoPProofValidator`, `ClaimValidator`
- `models/`: `AuthOptions`, `AuthenticationContext`, `HttpRequestInfo`, `AuthToken`
- `exception/`: `BaseAuthException` hierarchy (`InvalidTokenException`, `InsufficientScopeException`, etc.)
- `enums/`: `DPoPMode`, `AuthScheme`
- `examples/`: `Auth0ApiExample` (working HTTP server example)

**Spring Boot (`auth0-springboot-api/com/auth0/spring/boot/`)**:

- `Auth0AutoConfiguration`: Bean definitions and auto-configuration
- `Auth0Properties`: YAML configuration binding (`@ConfigurationProperties`)
- `Auth0AuthenticationFilter`: Spring Security filter integration
- `Auth0AuthenticationToken`: Spring Security authentication token

**Dependencies**:

- Core: `jackson-databind`, `httpclient`, `java-jwt`, `jwks-rsa`
- Spring: `spring-boot-starter-web`, `spring-boot-starter-security`

## Essential Reference Files

- **`JWT_VALIDATION_GUIDE.md`**: Complete JWT validation examples with working code
- **`auth0-api-java/src/main/java/com/auth0/examples/Auth0ApiExample.java`**: HTTP server with authentication
- **`auth0-springboot-api-playground/`**: Full Spring Boot integration example with SecurityConfig
- **Test files**: Comprehensive patterns for mocking JWKS, generating keypairs, testing DPoP proofs
