package com.ratelimiter.adaptive_rate_limiter.filter;

import com.ratelimiter.adaptive_rate_limiter.config.GatewayProperties;
import com.ratelimiter.adaptive_rate_limiter.model.ClientIdentity;
import com.ratelimiter.adaptive_rate_limiter.model.GatewayRequest;
import com.ratelimiter.adaptive_rate_limiter.model.GatewayResponse;
import com.ratelimiter.adaptive_rate_limiter.model.RateLimitRule;
import com.ratelimiter.adaptive_rate_limiter.ratelimit.RateLimitResult;
import com.ratelimiter.adaptive_rate_limiter.ratelimit.RateLimiterFactory;
import com.ratelimiter.adaptive_rate_limiter.risk.ClientBehaviorTracker;
import com.ratelimiter.adaptive_rate_limiter.risk.CompositeRiskScorer;
import com.ratelimiter.adaptive_rate_limiter.risk.RiskScore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Now adaptive — uses the risk score to dynamically
 * reduce the effective limit for suspicious clients.
 *
 * Flow:
 *  1. Read clientIdentity from request attribute
 *  2. Record this request in behavior tracker
 *  3. Compute risk score from behavior signals
 *  4. Apply throttle multiplier to base limit
 *  5. Call rate limiter with adjusted limit
 *  6. Allow or block
 */
@Slf4j
@Component
@Order(2)
@RequiredArgsConstructor
public class RateLimitFilter implements GatewayFilter {

    private final RateLimiterFactory      rateLimiterFactory;
    private final GatewayProperties       gatewayProperties;
    private final CompositeRiskScorer     riskScorer;
    private final ClientBehaviorTracker   behaviorTracker;

    @Override
    public GatewayResponse filter(GatewayRequest request) {

        // Step 1 — resolve client identity
        ClientIdentity identity = (ClientIdentity) request
                .getRawRequest()
                .getAttribute("clientIdentity");

        if (identity == null) {
            identity = ClientIdentity.anonymous(request.getRemoteIp());
        }

        // Step 2 — record this request for behavior tracking
        behaviorTracker.recordRequest(identity.getRateLimitKey());

        // Step 3 — compute risk score
        RiskScore riskScore = riskScorer.score(request);

        // Step 4 — build rule with risk-adjusted limit
        RateLimitRule rule = buildAdaptiveRule(identity, riskScore);

        if (!rule.isEnabled()) {
            return GatewayResponse.allowed();
        }

        // Step 5 — call the rate limiter
        RateLimitResult result = rateLimiterFactory
                .getLimiter(rule)
                .tryAcquire(identity.getRateLimitKey(), rule);

        log.info("RateLimit | client={} | path={} | allowed={} | " +
                        "remaining={}/{} | riskScore={} | multiplier={}",
                identity.getRateLimitKey(),
                request.getPath(),
                result.isAllowed(),
                result.getRemaining(),
                result.getLimit(),
                String.format("%.2f", riskScore.getScore()),
                String.format("%.2f", riskScore.getThrottleMultiplier()));

        if (result.isAllowed()) {
            return GatewayResponse.allowed();
        } else {
            return GatewayResponse.rateLimitExceeded(
                    result.getRetryAfterSeconds());
        }
    }

    @Override
    public String name() {
        return "RateLimitFilter";
    }

    /**
     * Builds a RateLimitRule where the limit is adjusted
     * downward based on the client's risk score.
     *
     * Example:
     *   Base limit   = 60 req/min
     *   Risk score   = 0.7 (high risk)
     *   Multiplier   = 0.3
     *   Effective    = 60 * 0.3 = 18 req/min
     */
    private RateLimitRule buildAdaptiveRule(ClientIdentity identity,
                                            RiskScore riskScore) {

        int baseLimit = switch (identity.getTier()) {
            case FREE     -> gatewayProperties
                    .getDefaultRules()
                    .getRequestsPerMinute();
            case STANDARD -> gatewayProperties
                    .getDefaultRules()
                    .getRequestsPerMinute() * 5;
            case PREMIUM  -> gatewayProperties
                    .getDefaultRules()
                    .getRequestsPerMinute() * 50;
        };

        // Apply throttle multiplier from risk score
        int effectiveLimit = (int) Math.max(1,
                baseLimit * riskScore.getThrottleMultiplier());

        String algorithmStr = gatewayProperties
                .getDefaultRules().getAlgorithm();
        RateLimitRule.Algorithm algorithm =
                RateLimitRule.Algorithm.valueOf(algorithmStr);

        if (riskScore.isMediumRisk() || riskScore.isHighRisk()) {
            log.info("Adaptive throttle | client={} | base={} | " +
                            "effective={} | reason={}",
                    identity.getRateLimitKey(),
                    baseLimit,
                    effectiveLimit,
                    riskScore.getReason());
        }

        return RateLimitRule.builder()
                .id("adaptive-" + identity.getTier().name().toLowerCase())
                .clientKey(identity.getRateLimitKey())
                .pathPattern("*")
                .requestsPerWindow(effectiveLimit)
                .windowSizeSeconds(60)
                .burstCapacity(riskScore.isHighRisk() ? 0
                        : gatewayProperties.getDefaultRules().getBurstCapacity())
                .algorithm(algorithm)
                .enabled(true)
                .build();
    }
}