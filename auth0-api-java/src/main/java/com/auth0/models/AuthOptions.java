package com.auth0.models;

import com.auth0.enums.DPoPMode;

public class AuthOptions {
    private final String domain;
    private final String audience;
    private final DPoPMode dpopMode;

    private final long dpopIatOffsetSeconds;
    private final long dpopIatLeewaySeconds;

    public AuthOptions(Builder builder) {
        this.domain = builder.domain;
        this.audience = builder.audience;
        this.dpopMode = builder.dpopMode;

        this.dpopIatOffsetSeconds = builder.dpopIatOffsetSeconds;
        this.dpopIatLeewaySeconds = builder.dpopIatLeewaySeconds;
    }

    public String getDomain() { return domain; }
    public String getAudience() { return audience; }
    public DPoPMode getDpopMode() { return dpopMode; }
    public long getDpopIatOffsetSeconds() { return dpopIatOffsetSeconds; }
    public long getDpopIatLeewaySeconds() { return dpopIatLeewaySeconds; }

    public static class Builder {
        private String domain;
        private String audience;
        private DPoPMode dpopMode = DPoPMode.ALLOWED;

        private long dpopIatOffsetSeconds = 300;
        private long dpopIatLeewaySeconds = 30;

        public Builder domain(String domain) {
            this.domain = domain;
            return this;
        }

        public Builder audience(String audience) {
            this.audience = audience;
            return this;
        }

        public Builder dpopMode(DPoPMode mode) {
            this.dpopMode = mode;
            return this;
        }

        public Builder dpopIatOffsetSeconds(long iatOffset) {
            if (iatOffset < 0) {
                throw new IllegalArgumentException("dpopIatOffsetSeconds must not be negative");
            }
            this.dpopIatOffsetSeconds = iatOffset;
            return this;
        }

        public Builder dpopIatLeewaySeconds(long iatLeeway) {
            if (iatLeeway < 0) {
                throw new IllegalArgumentException("dpopIatLeewaySeconds must not be negative");
            }
            this.dpopIatLeewaySeconds = iatLeeway;
            return this;
        }

        public AuthOptions build() {
            if (domain == null || domain.isEmpty()) {
                throw new IllegalArgumentException("Domain must not be null or empty");
            }
            if (audience == null || audience.isEmpty()) {
                throw new IllegalArgumentException("Audience must not be null or empty");
            }
            return new AuthOptions(this);
        }
    }
}
