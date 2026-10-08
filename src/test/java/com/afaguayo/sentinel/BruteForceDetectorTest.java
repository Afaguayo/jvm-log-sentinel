package com.afaguayo.sentinel;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BruteForceDetectorTest {

    private List<AuthEvent> loadSample() throws IOException {
        try (var in = getClass().getClassLoader().getResourceAsStream("samples/auth.log")) {
            assertNotNull(in, "sample fixture must be on the classpath");
            List<String> lines = new String(in.readAllBytes()).lines().toList();
            return new LogParser().parseLines(lines);
        }
    }

    @Test
    void flagsBruteForceBurstFromSingleIp() throws IOException {
        List<AuthEvent> events = loadSample();
        BruteForceDetector detector = new BruteForceDetector(Duration.ofMinutes(5), 5, 6);
        List<Finding> findings = detector.analyze(events);

        assertTrue(findings.stream().anyMatch(f ->
                f.sourceIp().equals("203.0.113.5") && f.type().equals("BRUTE_FORCE")));
    }

    @Test
    void flagsCredentialStuffingAcrossManyUsernames() throws IOException {
        List<AuthEvent> events = loadSample();
        BruteForceDetector detector = new BruteForceDetector(Duration.ofMinutes(5), 50, 6);
        List<Finding> findings = detector.analyze(events);

        assertTrue(findings.stream().anyMatch(f ->
                f.sourceIp().equals("198.51.100.9") && f.type().equals("CREDENTIAL_STUFFING")));
    }

    @Test
    void doesNotFlagSingleSuccessfulLogin() throws IOException {
        List<AuthEvent> events = loadSample();
        BruteForceDetector detector = new BruteForceDetector(Duration.ofMinutes(5), 5, 6);
        List<Finding> findings = detector.analyze(events);

        assertTrue(findings.stream().noneMatch(f -> f.sourceIp().equals("192.0.2.44")));
    }

    @Test
    void failuresByIpCountsCorrectly() throws IOException {
        List<AuthEvent> events = loadSample();
        BruteForceDetector detector = new BruteForceDetector(Duration.ofMinutes(5), 5, 6);
        var counts = detector.failuresByIp(events);
        assertEquals(6L, counts.get("203.0.113.5"));
        assertEquals(6L, counts.get("198.51.100.9"));
        assertNull(counts.get("192.0.2.44")); // successful login, not a failure
    }
}
