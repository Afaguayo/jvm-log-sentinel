package com.afaguayo.sentinel;

import java.time.LocalDateTime;
import java.time.Year;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses two common log formats into normalized {@link AuthEvent}s:
 *
 * <ul>
 *   <li>Linux sshd syslog lines, e.g.
 *       {@code Jun 14 03:22:11 host sshd[1234]: Failed password for root from 10.0.0.5 port 51515 ssh2}</li>
 *   <li>Apache/nginx combined access log lines, where a 401/403 status is treated
 *       as a failed authentication attempt and 2xx as success.</li>
 * </ul>
 *
 * Lines that match neither format are skipped (and counted as unparsed).
 */
public final class LogParser {

    private static final Pattern SSHD_FAILED = Pattern.compile(
            "^(?<ts>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+\\S+\\s+sshd\\[\\d+\\]:\\s+" +
                    "Failed password for (?:invalid user )?(?<user>\\S+) from (?<ip>[0-9a-fA-F.:]+) port \\d+.*");

    private static final Pattern SSHD_ACCEPTED = Pattern.compile(
            "^(?<ts>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+\\S+\\s+sshd\\[\\d+\\]:\\s+" +
                    "Accepted \\S+ for (?<user>\\S+) from (?<ip>[0-9a-fA-F.:]+) port \\d+.*");

    private static final DateTimeFormatter SYSLOG_FMT =
            DateTimeFormatter.ofPattern("MMM d HH:mm:ss");
    private static final DateTimeFormatter SYSLOG_FMT_PADDED =
            DateTimeFormatter.ofPattern("MMM  d HH:mm:ss");

    // Combined log format: IP - user [date] "METHOD path HTTP/1.1" status size
    private static final Pattern ACCESS_LOG = Pattern.compile(
            "^(?<ip>\\S+)\\s+\\S+\\s+(?<user>\\S+)\\s+\\[(?<ts>[^\\]]+)]\\s+" +
                    "\"(?<method>\\S+)\\s+(?<path>\\S+)\\s+\\S+\"\\s+(?<status>\\d{3})\\s+\\S+.*");

    private static final DateTimeFormatter ACCESS_FMT =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z");

    private int unparsedLines = 0;

    public int getUnparsedLines() {
        return unparsedLines;
    }

    public List<AuthEvent> parseLines(List<String> lines) {
        List<AuthEvent> events = new ArrayList<>();
        for (String line : lines) {
            AuthEvent event = parseLine(line);
            if (event != null) {
                events.add(event);
            } else if (!line.isBlank()) {
                unparsedLines++;
            }
        }
        return events;
    }

    public AuthEvent parseLine(String line) {
        Matcher m = SSHD_FAILED.matcher(line);
        if (m.matches()) {
            return new AuthEvent(parseSyslogTime(m.group("ts")), m.group("ip"), m.group("user"), false, line);
        }
        m = SSHD_ACCEPTED.matcher(line);
        if (m.matches()) {
            return new AuthEvent(parseSyslogTime(m.group("ts")), m.group("ip"), m.group("user"), true, line);
        }
        m = ACCESS_LOG.matcher(line);
        if (m.matches()) {
            int status = Integer.parseInt(m.group("status"));
            boolean authRelevant = status == 401 || status == 403 || (status >= 200 && status < 300);
            if (!authRelevant) {
                return null;
            }
            boolean success = status >= 200 && status < 300;
            String user = m.group("user");
            if ("-".equals(user)) {
                user = "anonymous";
            }
            return new AuthEvent(parseAccessTime(m.group("ts")), m.group("ip"), user, success, line);
        }
        return null;
    }

    private static LocalDateTime parseSyslogTime(String ts) {
        // Syslog timestamps have no year; assume current year.
        try {
            return LocalDateTime.parse(Year.now() + " " + ts,
                    DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss"));
        } catch (Exception e) {
            try {
                return LocalDateTime.parse(Year.now() + " " + ts,
                        DateTimeFormatter.ofPattern("yyyy MMM  d HH:mm:ss"));
            } catch (Exception e2) {
                return LocalDateTime.now();
            }
        }
    }

    private static LocalDateTime parseAccessTime(String ts) {
        try {
            return java.time.ZonedDateTime.parse(ts, ACCESS_FMT).toLocalDateTime();
        } catch (Exception e) {
            return LocalDateTime.now();
        }
    }
}
