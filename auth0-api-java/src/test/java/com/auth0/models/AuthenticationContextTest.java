package com.auth0.models;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class AuthenticationContextTest {

    @Test
    public void testGetActorReturnsNullWhenNoActClaim() {
        AuthenticationContext context = new AuthenticationContext(new HashMap<>());

        assertNull(context.getActor());
        assertTrue(context.getPriorActors().isEmpty());
    }

    @Test
    public void testGetActorReturnsTopLevelSubForSingleExchange() {
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", "mcp_server_client_id");
        Map<String, Object> claims = new HashMap<>();
        claims.put("act", act);

        AuthenticationContext context = new AuthenticationContext(claims);

        assertEquals("mcp_server_client_id", context.getActor());
        assertTrue(context.getPriorActors().isEmpty());
    }

    @Test
    public void testGetPriorActorsReturnsNestedActorsForChainedExchange() {
        Map<String, Object> spa = new LinkedHashMap<>();
        spa.put("sub", "spa_client_id");
        Map<String, Object> mcp1 = new LinkedHashMap<>();
        mcp1.put("sub", "mcp_server_1_client_id");
        mcp1.put("act", spa);
        Map<String, Object> mcp2 = new LinkedHashMap<>();
        mcp2.put("sub", "mcp_server_2_client_id");
        mcp2.put("act", mcp1);
        Map<String, Object> claims = new HashMap<>();
        claims.put("act", mcp2);

        AuthenticationContext context = new AuthenticationContext(claims);

        assertEquals("mcp_server_2_client_id", context.getActor());
        assertEquals(
                Arrays.asList("mcp_server_1_client_id", "spa_client_id"),
                context.getPriorActors());
    }

    @Test
    public void testGetActorReturnsNullWhenActIsNotAMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("act", "not-an-object");

        AuthenticationContext context = new AuthenticationContext(claims);

        assertNull(context.getActor());
        assertTrue(context.getPriorActors().isEmpty());
    }

    @Test
    public void testGetActorReturnsNullWhenActMissingSub() {
        Map<String, Object> spa = new LinkedHashMap<>();
        spa.put("sub", "spa_client_id");
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("act", spa);
        Map<String, Object> claims = new HashMap<>();
        claims.put("act", act);

        AuthenticationContext context = new AuthenticationContext(claims);

        assertNull(context.getActor());
        assertEquals(Arrays.asList("spa_client_id"), context.getPriorActors());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetPriorActorsReturnsUnmodifiableList() {
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("sub", "b");
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", "a");
        act.put("act", nested);
        Map<String, Object> claims = new HashMap<>();
        claims.put("act", act);

        AuthenticationContext context = new AuthenticationContext(claims);
        List<String> priors = context.getPriorActors();

        priors.add("mutate");
    }

    @Test
    public void testGetOrganizationIdReturnsOrgIdWhenPresent() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("org_id", "org_123");

        AuthenticationContext context = new AuthenticationContext(claims);

        assertEquals("org_123", context.getOrganizationId());
    }

    @Test
    public void testGetOrganizationIdReturnsNullWhenAbsent() {
        AuthenticationContext context = new AuthenticationContext(new HashMap<>());

        assertNull(context.getOrganizationId());
    }
}
