package com.afaguayo.sentinel;

import java.time.LocalDateTime;
import java.util.List;

/**
 * A detected suspicious pattern: either a brute-force burst (many failed
 * attempts against few/one username from one IP) or a credential-stuffing
 * spray (one IP failing against many distinct usernames).
 */
public record Finding(
        String type,
        String sourceIp,
        LocalDateTime windowStart,
        LocalDateTime windowEnd,
        int failedAttempts,
        List<String> usernamesTried
) {
    public String describe() {
        return String.format(
                "[%s] ip=%s failed=%d distinct_users=%d window=%s -> %s users=%s",
                type, sourceIp, failedAttempts, usernamesTried.size(), windowStart, windowEnd,
                usernamesTried.size() > 10
                        ? usernamesTried.subList(0, 10) + "...(+" + (usernamesTried.size() - 10) + ")"
                        : usernamesTried);
    }
}
