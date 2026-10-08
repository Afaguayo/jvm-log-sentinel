package com.afaguayo.sentinel;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Clusters failed-authentication events by source IP within a sliding time
 * window and flags two patterns:
 *
 * <ul>
 *   <li><b>BRUTE_FORCE</b>: {@code failThreshold} or more failed attempts
 *       from a single IP within {@code window}, mostly against one or a
 *       couple of usernames.</li>
 *   <li><b>CREDENTIAL_STUFFING</b>: {@code userThreshold} or more distinct
 *       usernames attempted from a single IP within {@code window}.</li>
 * </ul>
 */
public final class BruteForceDetector {

    private final Duration window;
    private final int failThreshold;
    private final int userThreshold;

    public BruteForceDetector(Duration window, int failThreshold, int userThreshold) {
        this.window = window;
        this.failThreshold = failThreshold;
        this.userThreshold = userThreshold;
    }

    public List<Finding> analyze(List<AuthEvent> events) {
        Map<String, List<AuthEvent>> byIp = events.stream()
                .filter(e -> !e.success())
                .collect(Collectors.groupingBy(AuthEvent::sourceIp));

        List<Finding> findings = new ArrayList<>();
        for (var entry : byIp.entrySet()) {
            String ip = entry.getKey();
            List<AuthEvent> sorted = entry.getValue().stream()
                    .sorted(Comparator.comparing(AuthEvent::timestamp))
                    .toList();

            // Sliding window scan: for each event, look at every later event
            // within `window` of it and accumulate the widest offending cluster.
            int n = sorted.size();
            int bestStart = -1, bestEnd = -1, bestCount = 0;
            int left = 0;
            for (int right = 0; right < n; right++) {
                while (sorted.get(right).timestamp().isAfter(
                        sorted.get(left).timestamp().plus(window))) {
                    left++;
                }
                int count = right - left + 1;
                if (count > bestCount) {
                    bestCount = count;
                    bestStart = left;
                    bestEnd = right;
                }
            }

            if (bestCount >= failThreshold || bestCount >= userThreshold) {
                List<AuthEvent> cluster = sorted.subList(bestStart, bestEnd + 1);
                Set<String> users = new LinkedHashSet<>();
                for (AuthEvent e : cluster) {
                    users.add(e.username());
                }
                String type = users.size() >= userThreshold ? "CREDENTIAL_STUFFING" : "BRUTE_FORCE";
                if (cluster.size() >= failThreshold || users.size() >= userThreshold) {
                    findings.add(new Finding(
                            type,
                            ip,
                            cluster.get(0).timestamp(),
                            cluster.get(cluster.size() - 1).timestamp(),
                            cluster.size(),
                            new ArrayList<>(users)));
                }
            }
        }
        findings.sort(Comparator.comparingInt(Finding::failedAttempts).reversed());
        return findings;
    }

    /** Convenience: total failed attempts per IP, for a quick top-offenders table. */
    public Map<String, Long> failuresByIp(List<AuthEvent> events) {
        Map<String, Long> counts = new TreeMap<>();
        for (AuthEvent e : events) {
            if (!e.success()) {
                counts.merge(e.sourceIp(), 1L, Long::sum);
            }
        }
        return counts;
    }
}
