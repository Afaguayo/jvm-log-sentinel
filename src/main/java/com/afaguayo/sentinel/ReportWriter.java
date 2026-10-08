package com.afaguayo.sentinel;

import java.util.List;
import java.util.Map;

/** Renders analysis results as either a human-readable text report or JSON. */
public final class ReportWriter {

    public String toText(List<AuthEvent> events, List<Finding> findings, Map<String, Long> topOffenders, int unparsed) {
        StringBuilder sb = new StringBuilder();
        sb.append("jvm-log-sentinel report\n");
        sb.append("========================\n");
        sb.append("Events parsed:   ").append(events.size()).append('\n');
        sb.append("Lines unparsed:  ").append(unparsed).append('\n');
        sb.append("Findings:        ").append(findings.size()).append("\n\n");

        if (findings.isEmpty()) {
            sb.append("No brute-force or credential-stuffing patterns detected.\n\n");
        } else {
            sb.append("Suspicious activity\n--------------------\n");
            for (Finding f : findings) {
                sb.append("- ").append(f.describe()).append('\n');
            }
            sb.append('\n');
        }

        sb.append("Top offending IPs by failed attempts\n-------------------------------------\n");
        topOffenders.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(10)
                .forEach(e -> sb.append(String.format("%-20s %d%n", e.getKey(), e.getValue())));

        return sb.toString();
    }

    public String toJson(List<AuthEvent> events, List<Finding> findings, Map<String, Long> topOffenders, int unparsed) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"eventsParsed\": ").append(events.size()).append(",\n");
        sb.append("  \"linesUnparsed\": ").append(unparsed).append(",\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("    {\n");
            sb.append("      \"type\": \"").append(f.type()).append("\",\n");
            sb.append("      \"sourceIp\": \"").append(f.sourceIp()).append("\",\n");
            sb.append("      \"windowStart\": \"").append(f.windowStart()).append("\",\n");
            sb.append("      \"windowEnd\": \"").append(f.windowEnd()).append("\",\n");
            sb.append("      \"failedAttempts\": ").append(f.failedAttempts()).append(",\n");
            sb.append("      \"usernamesTried\": [")
                    .append(String.join(", ", f.usernamesTried().stream().map(u -> "\"" + u + "\"").toArray(String[]::new)))
                    .append("]\n");
            sb.append("    }").append(i < findings.size() - 1 ? "," : "").append('\n');
        }
        sb.append("  ],\n");
        sb.append("  \"topOffenders\": {\n");
        var entries = topOffenders.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(10)
                .toList();
        for (int i = 0; i < entries.size(); i++) {
            var e = entries.get(i);
            sb.append("    \"").append(e.getKey()).append("\": ").append(e.getValue());
            sb.append(i < entries.size() - 1 ? ",\n" : "\n");
        }
        sb.append("  }\n");
        sb.append("}\n");
        return sb.toString();
    }
}
