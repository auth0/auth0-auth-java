package com.auth0.playground;

import com.auth0.spring.boot.Auth0AuthenticationToken;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProfileController {

    @GetMapping("/protected")
    public String protectedEndpoint(Authentication authentication) {
        System.out.println("🔐 Received request for protected resource: "+ authentication.getPrincipal().toString());
        return "Hello " + authentication.getName() + ", access granted!";
    }

    @GetMapping("/public")
    public Map<String, Object> pub() {
        return Map.of("message", "Public endpoint — no token required");
    }

    /**
     * MCD-protected endpoint — identical to {@code /api/protected} but
     * demonstrates that the same controller works seamlessly with
     * Multi-Custom Domain configurations.
     * <p>
     * When a {@link com.auth0.DomainResolver} bean is
     * defined, the SDK resolves the allowed issuer domains dynamically.
     * This endpoint does not need any MCD-specific code.
     * </p>
     */
    @GetMapping("/mcd-protected")
    public ResponseEntity<Map<String, Object>> mcdProtectedEndpoint(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "MCD access granted!");
        response.put("user", authentication.getName());
        response.put("authenticated", true);

        if (authentication instanceof Auth0AuthenticationToken) {
            Auth0AuthenticationToken auth0Token = (Auth0AuthenticationToken) authentication;
            response.put("issuer", auth0Token.getClaim("iss"));
        }

        return ResponseEntity.ok(response);
    }
}