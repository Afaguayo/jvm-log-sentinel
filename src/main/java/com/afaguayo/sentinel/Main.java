package com.afaguayo.sentinel;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * CLI entry point.
 *
 * <pre>
 *   java -jar jvm-log-sentinel.jar --input access.log [--window-minutes 5]
 *        [--fail-threshold 5] [--user-threshold 6] [--json] [--out report.txt]
 * </pre>
 */
public final class Main {

    public static void main(String[] args) throws IOException {
        String input = null;
        int windowMinutes = 5;
        int failThreshold = 5;
        int userThreshold = 6;
        boolean json = false;
        String out = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--input" -> input = args[++i];
                case "--window-minutes" -> windowMinutes = Integer.parseInt(args[++i]);
                case "--fail-threshold" -> failThreshold = Integer.parseInt(args[++i]);
                case "--user-threshold" -> userThreshold = Integer.parseInt(args[++i]);
                case "--json" -> json = true;
                case "--out" -> out = args[++i];
                case "--help", "-h" -> {
                    printHelp();
                    return;
                }
                default -> {
                    System.err.println("Unknown argument: " + args[i]);
                    printHelp();
                    System.exit(1);
                }
            }
        }

        if (input == null) {
            System.err.println("Error: --input <logfile> is required.\n");
            printHelp();
            System.exit(1);
            return;
        }

        List<String> lines = Files.readAllLines(Path.of(input));
        LogParser parser = new LogParser();
        List<AuthEvent> events = parser.parseLines(lines);

        BruteForceDetector detector = new BruteForceDetector(
                Duration.ofMinutes(windowMinutes), failThreshold, userThreshold);
        var findings = detector.analyze(events);
        var topOffenders = detector.failuresByIp(events);

        ReportWriter writer = new ReportWriter();
        String report = json
                ? writer.toJson(events, findings, topOffenders, parser.getUnparsedLines())
                : writer.toText(events, findings, topOffenders, parser.getUnparsedLines());

        if (out != null) {
            Files.writeString(Path.of(out), report);
            System.out.println("Report written to " + out);
        } else {
            System.out.print(report);
        }

        if (!findings.isEmpty()) {
            System.exit(2); // non-zero exit so CI/cron jobs can alert on findings
        }
    }

    private static void printHelp() {
        System.out.println("""
                jvm-log-sentinel - authentication log brute-force / credential-stuffing detector

                Usage:
                  java -jar jvm-log-sentinel.jar --input <logfile> [options]

                Options:
                  --input <file>           Log file to analyze (sshd syslog or Apache/nginx combined access log)
                  --window-minutes <n>      Sliding time window in minutes (default 5)
                  --fail-threshold <n>      Failed attempts from one IP within the window to flag brute force (default 5)
                  --user-threshold <n>      Distinct usernames from one IP within the window to flag credential stuffing (default 6)
                  --json                    Emit JSON instead of text
                  --out <file>              Write report to file instead of stdout
                  --help                    Show this help

                Exit codes:
                  0   no findings
                  2   findings detected (useful for scripting/alerting)
                  1   usage error
                """);
    }
}
