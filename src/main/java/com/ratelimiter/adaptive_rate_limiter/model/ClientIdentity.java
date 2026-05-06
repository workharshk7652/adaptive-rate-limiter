package com.ratelimiter.adaptive_rate_limiter.model;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Builder
@Getter
@ToString
public class ClientIdentity {

    private final String apiKey;
    private final String clientName;
    private final ClientTier tier;
    private final String ipAddress;

    public String getRateLimitKey() {
        if (apiKey != null && !apiKey.isBlank()) {
            return "client:" + apiKey;
        }
        return "ip:" + ipAddress;
    }

    public boolean isAuthenticated() {
        return apiKey != null && !apiKey.isBlank();
    }

    public static ClientIdentity anonymous(String ipAddress) {
        return ClientIdentity.builder()
                .ipAddress(ipAddress)
                .clientName("anonymous:" + ipAddress)
                .tier(ClientTier.FREE)
                .build();
    }

    public enum ClientTier {
        FREE(60),
        STANDARD(500),
        PREMIUM(5000);

        private final int defaultRequestsPerMinute;

        ClientTier(int rpm) {
            this.defaultRequestsPerMinute = rpm;
        }

        public int getDefaultRequestsPerMinute() {
            return defaultRequestsPerMinute;
        }
    }
}
