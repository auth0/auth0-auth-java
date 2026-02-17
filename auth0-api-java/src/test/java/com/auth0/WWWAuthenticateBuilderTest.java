package com.auth0;

import com.auth0.enums.DPoPMode;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class WWWAuthenticateBuilderTest {

    @Test
    public void buildChallenges_shouldUseBearerOnly_whenDisabled() {
        List<String> result = WWWAuthenticateBuilder.buildChallenges("invalid_token", "Invalid", DPoPMode.DISABLED, null);
        assertThat(result).containsExactly("Bearer realm=\"api\", error=\"invalid_token\", error_description=\"Invalid\"");

        result = WWWAuthenticateBuilder.buildChallenges("unauthorized", "Desc", DPoPMode.DISABLED, null);
        assertThat(result).containsExactly("Bearer realm=\"api\"");

        result = WWWAuthenticateBuilder.buildChallenges(null, "Desc", DPoPMode.DISABLED, null);
        assertThat(result).containsExactly("Bearer realm=\"api\"");

        result = WWWAuthenticateBuilder.buildChallenges("invalid", null, DPoPMode.DISABLED, null);
        assertThat(result).containsExactly("Bearer realm=\"api\"");
    }

    @Test
    public void buildChallenges_shouldUseDpopOnly_whenRequired() {
        List<String> result = WWWAuthenticateBuilder.buildChallenges("err", "desc", DPoPMode.REQUIRED, null);
        assertThat(result).containsExactly(
                "DPoP error=\"err\", error_description=\"desc\", algs=\"ES256\""
        );

        result = WWWAuthenticateBuilder.buildChallenges(null, null, DPoPMode.REQUIRED, null);
        assertThat(result).containsExactly("DPoP algs=\"ES256\"");
    }

    @Test
    public void buildChallenges_shouldUseBearerAndDpop_whenAllowedOrOther() {
        List<String> result = WWWAuthenticateBuilder.buildChallenges("err", "desc", DPoPMode.ALLOWED, "bearer");
        assertThat(result).containsExactly(
                "Bearer error=\"err\", error_description=\"desc\"",
                "DPoP algs=\"ES256\""
        );

        result = WWWAuthenticateBuilder.buildChallenges(null, null, DPoPMode.ALLOWED, "bearer");
        assertThat(result).containsExactly(
                "Bearer realm=\"api\"",
                "DPoP algs=\"ES256\""
        );

        result = WWWAuthenticateBuilder.buildChallenges("err", "desc", DPoPMode.ALLOWED, "dpop");
        assertThat(result).containsExactly(
                "Bearer realm=\"api\"",
                "DPoP error=\"err\", error_description=\"desc\", algs=\"ES256\""
        );

        result = WWWAuthenticateBuilder.buildChallenges(null, null, DPoPMode.ALLOWED, "dpop");
        assertThat(result).containsExactly(
                "Bearer realm=\"api\"",
                "DPoP algs=\"ES256\""
        );

        result = WWWAuthenticateBuilder.buildChallenges(null, null, DPoPMode.ALLOWED, "unknown");
        assertThat(result).containsExactly(
                "Bearer realm=\"api\"",
                "DPoP algs=\"ES256\""
        );
    }

    @Test
    public void escape_shouldEscapeBackslashAndQuotes() throws Exception {
        java.lang.reflect.Method method = WWWAuthenticateBuilder.class.getDeclaredMethod("escape", String.class);
        method.setAccessible(true);

        String input = "foo\\bar\"test";
        String escaped = (String) method.invoke(null, input);

        assertThat(escaped).isEqualTo("foo\\\\bar\\\"test");
    }
}
