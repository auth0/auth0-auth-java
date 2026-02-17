# Auth0 Spring Boot API Examples

This document provides examples for using the `auth0-springboot-api` package to validate Auth0 tokens in your Spring Boot applications.

## Basic Configuration

Configure your Auth0 settings in `application.yml`:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
```

Or in `application.properties`:

```properties
auth0.domain=your-tenant.auth0.com
auth0.audience=https://api.example.com
```

## Bearer Authentication

Bearer authentication is the standard OAuth 2.0 token authentication method.

### Basic Setup

```java
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(
            HttpSecurity http,
            Auth0AuthenticationFilter authFilter
    ) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/protected").authenticated()
                    .requestMatchers("/api/public").permitAll()
                    .anyRequest().authenticated()
                )
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### Protected Endpoint Example

```java
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint(Authentication authentication) {
        String userId = authentication.getName(); // Returns the 'sub' claim

        return ResponseEntity.ok(Map.of(
            "message", "Access granted!",
            "user", userId,
            "authenticated", true
        ));
    }

    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        return ResponseEntity.ok(Map.of(
            "message", "Public endpoint - no token required"
        ));
    }
}
```

### Accessing Token Claims

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile(Authentication authentication) {
        if (authentication instanceof Auth0AuthenticationToken) {
            Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;
            DecodedJWT jwt = auth0Token.getJwt();

            return ResponseEntity.ok(Map.of(
                "sub", jwt.getSubject(),
                "email", jwt.getClaim("email").asString(),
                "scope", jwt.getClaim("scope").asString(),
                "exp", jwt.getExpiresAt(),
                "iat", jwt.getIssuedAt()
            ));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

### Custom Error Handling

```java
@ControllerAdvice
public class AuthErrorHandler {

    @ExceptionHandler(BaseAuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(BaseAuthException ex) {
        Map<String, Object> error = Map.of(
            "error", ex.getError(),
            "error_description", ex.getMessage(),
            "status", ex.getStatusCode()
        );

        HttpHeaders headers = new HttpHeaders();
        if (ex.getWwwAuthenticateHeader() != null) {
            headers.add("WWW-Authenticate", ex.getWwwAuthenticateHeader());
        }

        return new ResponseEntity<>(error, headers, HttpStatus.valueOf(ex.getStatusCode()));
    }
}
```

## DPoP Authentication

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Possession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens.

### Configuration Modes

#### 1. Allowed Mode (Default)

Accepts both Bearer and DPoP tokens:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpopMode: ALLOWED # Default value
```

#### 2. Required Mode

Only accepts DPoP tokens:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpopMode: REQUIRED
```

#### 3. Disabled Mode

Only accepts Bearer tokens:

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpopMode: DISABLED
```

### Advanced DPoP Configuration

```yaml
auth0:
  domain: "your-tenant.auth0.com"
  audience: "https://api.example.com"
  dpopMode: ALLOWED
  dpopIatOffsetSeconds: 300 # DPoP proof time window (default: 300)
  dpopIatLeewaySeconds: 30 # DPoP proof time leeway (default: 30)
```

### DPoP-Token Controller

```java
@RestController
@RequestMapping("/api")
public class DPoPController {

    @GetMapping("/sensitive")
    public ResponseEntity<Map<String, Object>> sensitiveEndpoint(
            Authentication authentication,
            HttpServletRequest request
    ) {
        if (authentication instanceof Auth0AuthenticationToken) {
            Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;
            AuthenticationContext context = auth0Token.getAuthenticationContext();

            Map<String, Object> response = new HashMap<>();
            response.put("user", authentication.getName());
            response.put("scheme", context.getScheme().toString());

            if (context.getScheme() == AuthScheme.DPOP) {
                response.put("message", "Access granted with DPoP proof");
                response.put("dpop_bound", true);
            } else {
                response.put("message", "Access granted with Bearer token");
                response.put("dpop_bound", false);
            }

            return ResponseEntity.ok(response);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

## Scope-Based Authorization

### Method-Level Security

```java
@RestController
@RequestMapping("/api")
@PreAuthorize("hasAuthority('SCOPE_read:users')")
public class UserManagementController {

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_read:users')")
    public ResponseEntity<List<User>> getUsers() {
        // Only accessible with 'read:users' scope
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PostMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_write:users')")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        // Only accessible with 'write:users' scope
        return ResponseEntity.ok(userService.createUser(user));
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('SCOPE_delete:users')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        // Only accessible with 'delete:users' scope
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

### Custom Scope Validation

```java
@Component
public class ScopeValidator {

    public boolean hasRequiredScopes(Authentication authentication, String... requiredScopes) {
        if (!(authentication instanceof Auth0AuthenticationToken)) {
            return false;
        }

        Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;
        DecodedJWT jwt = auth0Token.getJwt();
        String scopeClaim = jwt.getClaim("scope").asString();

        if (scopeClaim == null) {
            return false;
        }

        Set<String> tokenScopes = Set.of(scopeClaim.split(" "));
        return tokenScopes.containsAll(Arrays.asList(requiredScopes));
    }
}

@RestController
@RequestMapping("/api")
public class CustomScopeController {

    @Autowired
    private ScopeValidator scopeValidator;

    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> adminEndpoint(Authentication authentication) {
        if (!scopeValidator.hasRequiredScopes(authentication, "admin", "read:admin")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "insufficient_scope"));
        }

        return ResponseEntity.ok(Map.of("message", "Admin access granted"));
    }
}
```

## Testing

### Unit Test Example

```java
@WebMvcTest(ApiController.class)
class ApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private Auth0AuthenticationFilter authFilter;

    @Test
    void testProtectedEndpointWithValidToken() throws Exception {
        // Mock authentication
        Auth0AuthenticationToken mockAuth = mock(Auth0AuthenticationToken.class);
        when(mockAuth.getName()).thenReturn("user123");
        when(mockAuth.isAuthenticated()).thenReturn(true);

        mockMvc.perform(get("/api/protected")
                .with(authentication(mockAuth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("user123"))
                .andExpect(jsonPath("$.authenticated").value(true));
    }

    @Test
    void testPublicEndpoint() throws Exception {
        mockMvc.perform(get("/api/public"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Public endpoint - no token required"));
    }
}
```

### Integration Test Example

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
    "auth0.domain=test-tenant.auth0.com",
    "auth0.audience=https://test-api.example.com",
    "auth0.dpopMode=ALLOWED"
})
class AuthIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void testProtectedEndpointWithBearerToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + getValidJwtToken());

        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(
            "/api/protected",
            HttpMethod.GET,
            entity,
            Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("user");
    }

    @Test
    void testProtectedEndpointWithDPoPToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "DPoP " + getValidDPoPToken());
        headers.add("DPoP", getValidDPoPProof());

        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(
            "/api/protected",
            HttpMethod.GET,
            entity,
            Map.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("user");
    }

    private String getValidJwtToken() {
        // Generate or mock a valid JWT token for testing
        // Implementation depends on your testing strategy
        return "eyJ0eXAiOiJKV1Q...";
    }

    private String getValidDPoPToken() {
        // Generate or mock a valid DPoP-bound access token
        return "eyJ0eXAiOiJKV1Q...";
    }

    private String getValidDPoPProof() {
        // Generate or mock a valid DPoP proof
        return "eyJ0eXAiOiJkcG9wK2p3dCI...";
    }
}
```

## Configuration Reference

### Complete Configuration Example

```yaml
auth0:
  # Required: Your Auth0 domain
  domain: "your-tenant.auth0.com"

  # Required: API identifier/audience
  audience: "https://api.example.com"

  # Optional: DPoP mode (DISABLED, ALLOWED, REQUIRED)
  # Default: ALLOWED
  dpopMode: ALLOWED

  # Optional: DPoP proof time window in seconds
  # Default: 300 (5 minutes)
  dpopIatOffsetSeconds: 300

  # Optional: DPoP proof time leeway in seconds
  # Default: 30 (30 seconds)
  dpopIatLeewaySeconds: 30
```

### Environment Variables

You can also configure using environment variables:

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://api.example.com
AUTH0_DPOP_MODE=ALLOWED
AUTH0_DPOP_IAT_OFFSET_SECONDS=300
AUTH0_DPOP_IAT_LEEWAY_SECONDS=30
```

## Error Handling

### Common HTTP Status Codes

- **401 Unauthorized**: Missing or invalid token
- **403 Forbidden**: Valid token but insufficient permissions
- **400 Bad Request**: Invalid DPoP proof or malformed request

### WWW-Authenticate Headers

The library automatically sets appropriate `WWW-Authenticate` headers:

```
# ALLOWED mode (default)
WWW-Authenticate: Bearer realm="api", DPoP algs="ES256"

# REQUIRED mode
WWW-Authenticate: DPoP algs="ES256"

# DPoP-specific errors
WWW-Authenticate: DPoP error="invalid_dpop_proof", error_description="DPoP proof validation failed"
```

## Best Practices

1. **Environment-Specific Configuration**: Use different Auth0 domains and audiences for different environments
2. **Scope Validation**: Always validate scopes for sensitive operations
3. **Error Handling**: Implement comprehensive error handling for auth failures
4. **Testing**: Use mocked authentication for unit tests and real tokens for integration tests
5. **Security Headers**: Ensure proper CORS and security headers are configured
6. **DPoP Mode**: Use `REQUIRED` mode for high-security APIs, `ALLOWED` for gradual adoption
