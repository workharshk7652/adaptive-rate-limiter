package com.ratelimiter.adaptive_rate_limiter.ratelimit;

import com.ratelimiter.adaptive_rate_limiter.model.RateLimitRule;

/**
 * Common interface for all rate limiting algorithms.
 *
 * Why an interface?
 * RateLimiterFactory returns this type. The filter chain
 * calls tryAcquire() without knowing which algorithm is running.
 * Swap TOKEN_BUCKET to SLIDING_WINDOW in the rule — behavior
 * changes, zero code changes in the filter.
 */
public interface RateLimiter {

    /**
     * @param clientKey  Redis key prefix e.g. "client:abc123" or "ip:1.2.3.4"
     * @param rule       Contains limit, window size, burst capacity
     * @return           Result with allowed/denied + remaining quota
     */
    RateLimitResult tryAcquire(String clientKey, RateLimitRule rule);
}