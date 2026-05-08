package com.ratelimiter.adaptive_rate_limiter.filter;

import com.ratelimiter.adaptive_rate_limiter.config.GatewayProperties;
import com.ratelimiter.adaptive_rate_limiter.controller.AdminController;
import com.ratelimiter.adaptive_rate_limiter.model.ClientIdentity;
import com.ratelimiter.adaptive_rate_limiter.model.GatewayRequest;
import com.ratelimiter.adaptive_rate_limiter.model.GatewayResponse;
import com.ratelimiter.adaptive_rate_limiter.model.RateLimitRule;
import com.ratelimiter.adaptive_rate_limiter.ratelimit.RateLimitResult;
import com.ratelimiter.adaptive_rate_limiter.ratelimit.RateLimiterFactory;
import com.ratelimiter.adaptive_rate_limiter.risk.ClientBehaviorTracker;
import com.ratelimiter.adaptive_rate_limiter.risk.CompositeRiskScorer;
import com.ratelimiter.adaptive_rate_limiter.risk.RiskScore;
import com.ratelimiter.adaptive_rate_limiter.shadow.ShadowModeEvaluator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Order(2)
@RequiredArgsConstructor
public class RateLimitFilter implements GatewayFilter {

    private final RateLimiterFactory    rateLimiterFactory;
    private final GatewayProperties     gatewayProperties;
    private final CompositeRiskScorer   riskScorer;
    private final ClientBehaviorTracker behaviorTracker;
    private final ShadowModeEvaluator   shadowModeEvaluator;
    private final AdminController       adminController;

    @Override
    public GatewayResponse filter(GatewayRequest request) {

        // Step 1 — resolve client identity
        ClientIdentity identity = (ClientIdentity) request
                .getRawRequest()
                .getAttribute("clientIdentity");

        if (identity == null) {
            identity = ClientIdentity.anonymous(request.getRemoteIp());
        }

        // Step 2 — record request for behavior tracking
        behaviorTracker.recordRequest(identity.getRateLimitKey());

        // Step 3 — compute risk score
        RiskScore riskScore = riskScorer.score(request);

        // Step 4 — build adaptive rule
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

        // Step 6 — raw decision
        GatewayResponse decision = result.isAllowed()
                ? GatewayResponse.allowed()
                : GatewayResponse.rateLimitExceeded(
                result.getRetryAfterSeconds());

        // Store raw decision so ShadowModeFilter can read it globally
        request.getRawRequest().setAttribute("rateLimitDecision", decision);

        // Step 7 — shadow mode check
        return shadowModeEvaluator.evaluate(request, decision, rule);
    }

    @Override
    public String name() {
        return "RateLimitFilter";
    }

    private RateLimitRule buildAdaptiveRule(ClientIdentity identity,
                                            RiskScore riskScore) {

        // Check if a custom rule exists for this client in Admin API
        RateLimitRule customRule = adminController
                .findRuleForClient(identity.getRateLimitKey());

        if (customRule != null) {
            log.debug("Using custom rule | id={} | shadowMode={} | limit={}/{}s",
                    customRule.getId(),
                    customRule.isShadowMode(),
                    customRule.getRequestsPerWindow(),
                    customRule.getWindowSizeSeconds());

            // Apply risk score multiplier even to custom rules
            int effectiveLimit = (int) Math.max(1,
                    customRule.getRequestsPerWindow()
                            * riskScore.getThrottleMultiplier());

            return RateLimitRule.builder()
                    .id(customRule.getId())
                    .clientKey(identity.getRateLimitKey())
                    .pathPattern(customRule.getPathPattern())
                    .requestsPerWindow(effectiveLimit)
                    .windowSizeSeconds(customRule.getWindowSizeSeconds())
                    .burstCapacity(riskScore.isHighRisk() ? 0
                            : customRule.getBurstCapacity())
                    .algorithm(customRule.getAlgorithm())
                    .shadowMode(customRule.isShadowMode())  // ← preserved correctly
                    .enabled(customRule.isEnabled())
                    .build();
        }

        int baseLimit = switch (identity.getTier()) {
            case FREE     -> gatewayProperties
                    .getDefaultRules().getRequestsPerMinute();
            case STANDARD -> gatewayProperties
                    .getDefaultRules().getRequestsPerMinute() * 5;
            case PREMIUM  -> gatewayProperties
                    .getDefaultRules().getRequestsPerMinute() * 50;
        };

        int effectiveLimit = (int) Math.max(1,
                baseLimit * riskScore.getThrottleMultiplier());

        RateLimitRule.Algorithm algorithm = RateLimitRule.Algorithm.valueOf(
                gatewayProperties.getDefaultRules().getAlgorithm());

        if (riskScore.isMediumRisk() || riskScore.isHighRisk()) {
            log.info("Adaptive throttle | client={} | base={} | effective={} | reason={}",
                    identity.getRateLimitKey(),
                    baseLimit, effectiveLimit,
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
                .shadowMode(false)
                .enabled(true)
                .build();
    }
}