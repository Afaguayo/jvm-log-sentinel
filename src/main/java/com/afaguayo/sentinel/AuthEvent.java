package com.afaguayo.sentinel;

import java.time.LocalDateTime;

/**
 * A single normalized authentication attempt extracted from a log line,
 * regardless of whether it came from sshd or a web server access log.
 */
public record AuthEvent(
        LocalDateTime timestamp,
        String sourceIp,
        String username,
        boolean success,
        String raw
) {
}
