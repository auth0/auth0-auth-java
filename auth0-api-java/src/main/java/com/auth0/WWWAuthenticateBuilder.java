package com.auth0;

import com.auth0.enums.DPoPMode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class WWWAuthenticateBuilder {

    private static final List<String> DPOP_ALGS = Arrays.asList("ES256");

    public static List<String> buildChallenges(String errorCode, String errorDescription, DPoPMode dpopMode, String scheme) {

        boolean omitError = errorDescription == null || errorDescription.isEmpty() || errorCode == null || errorCode.isEmpty();

        if(dpopMode.equals(DPoPMode.DISABLED)){
            return buildBearerOnly(errorCode, errorDescription, omitError);
        }
        else if (dpopMode.equals(DPoPMode.REQUIRED)){
            return buildDpopOnly(errorCode, errorDescription);
        }
        else {
            return buildBearerAndDpop(errorCode, errorDescription, scheme);
        }
    }

    private static List<String> buildBearerOnly(String errorCode, String errorDescription, boolean omitError) {
        List<String> out = new ArrayList<>();
        String realm = "realm=\"api\"";


        if (errorCode != null && !"unauthorized".equals(errorCode) && !omitError) {
            String err = "error=\"" + errorCode + "\", error_description=\"" + escape(errorDescription) + "\"";
            out.add("Bearer " + realm + ", " + err);
        } else {
            out.add("Bearer " + realm);
        }
        return out;
    }

    private static List<String> buildBearerAndDpop(
            String errorCode,
            String errorDescription,
            String authScheme
    ) {
        List<String> out = new ArrayList<>();
        String realm = "realm=\"api\"";
        String algs = String.join(" ", DPOP_ALGS);

        // Determine if we should include error parameters on Bearer
        boolean includeError = errorCode != null && !errorCode.isEmpty() &&
                errorDescription != null && !errorDescription.isEmpty();

        if ("bearer".equalsIgnoreCase(authScheme)) {
            String bearerHeader = "";
            if (includeError) {
                bearerHeader = "Bearer error=\"" + errorCode + "\", error_description=\"" + escape(errorDescription) + "\"";
            } else {
                bearerHeader = "Bearer " + realm;
            }
            out.add(bearerHeader);

            out.add("DPoP algs=\"" + algs + "\"");
            return out;
        }

        if ("dpop".equalsIgnoreCase(authScheme)) {
            out.add("Bearer " + realm);

            String dpopHeader = "DPoP";
            if (includeError) {
                dpopHeader += " error=\"" + errorCode + "\", error_description=\"" + escape(errorDescription) + "\", algs=\"" + algs + "\"";
            } else {
                dpopHeader += " algs=\"" + algs + "\"";
            }
            out.add(dpopHeader);
            return out;
        }

        out.add("Bearer " + realm);
        out.add("DPoP algs=\"" + algs + "\"");
        return out;
    }

    public static List<String> buildDpopOnly(String errorCode, String errorDescription) {
        List<String> out = new ArrayList<>();
        String algs = String.join(" ", DPOP_ALGS);

        String dpopHeader = "DPoP";

        boolean includeError = errorCode != null && !errorCode.isEmpty() &&
                errorDescription != null && !errorDescription.isEmpty();

        if (includeError) {
            dpopHeader += " error=\"" + errorCode + "\", error_description=\"" + escape(errorDescription) + "\", algs=\"" + algs + "\"";
        } else {
            dpopHeader += " algs=\"" + algs + "\"";
        }
        out.add(dpopHeader);

        return out;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
