package com.auth0.models;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AuthenticationContext {
    private final Map<String, Object> claims;

    public AuthenticationContext(Map<String, Object> claims) {
        this.claims = claims;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    /**
     * Returns the current actor from the RFC 8693 {@code act} claim (the top-level {@code act.sub}).
     *
     * <p>For a token issued via On-Behalf-Of token exchange, this identifies the party that
     * performed the exchange. Per RFC 8693 §4.1, this is the only actor that should be used for
     * access control decisions.
     *
     * @return the current actor identifier, or {@code null} if the token has no {@code act} claim
     */
    public String getActor() {
        Object act = claims.get("act");
        if (act instanceof Map) {
            Object sub = ((Map<?, ?>) act).get("sub");
            if (sub instanceof String) {
                return (String) sub;
            }
        }
        return null;
    }

    /**
     * Returns the prior actors in the RFC 8693 delegation chain, ordered from the most recent
     * (nearest to the current actor) to the original.
     *
     * <p>These are the actors nested inside the {@code act} claim. Per RFC 8693 §4.1 they are
     * informational only and MUST NOT be used for access control decisions; use them for audit
     * logging only.
     *
     * @return an unmodifiable list of prior actor identifiers, or an empty list if there are none
     */
    public List<String> getPriorActors() {
        List<String> priorActors = new ArrayList<>();
        Object node = claims.get("act");
        while (node instanceof Map) {
            node = ((Map<?, ?>) node).get("act");
            if (node instanceof Map) {
                Object sub = ((Map<?, ?>) node).get("sub");
                if (sub instanceof String) {
                    priorActors.add((String) sub);
                }
            }
        }
        return Collections.unmodifiableList(priorActors);
    }

    /**
     * Returns the organization identifier from the {@code org_id} claim, if present.
     *
     * <p>Organization membership and RBAC policies are enforced by Auth0 when the token is issued;
     * this accessor simply exposes the preserved organization context for the caller to read.
     *
     * @return the {@code org_id} claim value, or {@code null} if the token is not organization-bound
     */
    public String getOrganizationId() {
        Object orgId = claims.get("org_id");
        return (orgId instanceof String) ? (String) orgId : null;
    }
}
