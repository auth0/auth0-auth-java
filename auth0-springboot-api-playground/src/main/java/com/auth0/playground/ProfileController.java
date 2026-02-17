package com.auth0.playground;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
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
}