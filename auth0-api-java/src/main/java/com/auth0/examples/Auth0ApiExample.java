package com.auth0.examples;

import com.auth0.AuthClient;
import com.auth0.enums.DPoPMode;
import com.auth0.exception.BaseAuthException;
import com.auth0.models.AuthOptions;
import com.auth0.models.AuthenticationContext;
import com.auth0.models.HttpRequestInfo;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

public class Auth0ApiExample {

    private static final String DOMAIN = "your-tenant.auth0.com";
    private static final String AUDIENCE = "https://your-api-identifier";

    public static void main(String[] args) throws Exception {

        // Create simple HTTP server on port 8080
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);

        // Public endpoint
        server.createContext("/open-endpoint", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                sendResponse(exchange, "Open endpoint: no authentication needed", 200);
            }
        });

        // Build Auth0 options -> AuthClient
        AuthOptions options = new AuthOptions.Builder()
                .domain(DOMAIN)
                .audience(AUDIENCE)
                .dpopMode(DPoPMode.REQUIRED)
                .dpopIatOffsetSeconds(300)
                .dpopIatLeewaySeconds(30)// or REQUIRED / DISABLED
                .build();

        AuthClient client = AuthClient.from(options);

        // Protected endpoint
        server.createContext("/api/protected",
                new AuthHandler(client));

        server.setExecutor(null);  // Default executor
        server.start();

        System.out.println("🚀 Server started on http://localhost:8000");
        System.out.println("➡ Try:");
        System.out.println("   curl http://localhost:8000/open-endpoint");
        System.out.println("   curl -H \"Authorization: Bearer <token>\" http://localhost:8000/restricted-endpoint");
    }

    private static void sendResponse(HttpExchange exchange, String response, int statusCode)
            throws IOException {

        byte[] bytes = response.getBytes("UTF-8");

        exchange.sendResponseHeaders(statusCode, bytes.length);

        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    static class AuthHandler implements HttpHandler {

        private final AuthClient authClient;

        public AuthHandler(AuthClient authClient) {
            this.authClient = authClient;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {

            // Normalize headers (lowercase keys)
            Map<String, String> headers = new HashMap<String, String>();

            String auth = exchange.getRequestHeaders().getFirst("Authorization");

            headers.put("authorization", auth);


            String dpopHeader = exchange.getRequestHeaders().getFirst("DPoP");

            if(dpopHeader != null) {
                headers.put("DPoP", dpopHeader);
            }


            // Build HttpRequestInfo (needed for DPoP htm + htu validation)
            HttpRequestInfo requestInfo = new HttpRequestInfo(
                    exchange.getRequestMethod(),
                    "http://localhost:8000" + exchange.getRequestURI().toString(), null
            );

            System.out.println("Incoming request to " + requestInfo.toString());

            try {
                AuthenticationContext claims =
                        authClient.verifyRequest(headers, requestInfo);

                String user = (String) claims.getClaims().get("sub");

                sendResponse(exchange,
                        "Authenticated access granted! User: " + user,
                        200);

            } catch (BaseAuthException e) {
                sendResponse(exchange, String.valueOf(e.getHeaders()),
                        e.getStatusCode());

            } catch (IllegalArgumentException e) {
                sendResponse(exchange,
                        "Bad request: " + e.getMessage(),
                        400);
            }
        }
    }
}