package com.afaguayo.sentinel;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LogParserTest {

    @Test
    void parsesFailedSshdLine() {
        LogParser parser = new LogParser();
        AuthEvent event = parser.parseLine(
                "Jun 14 03:22:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 51515 ssh2");
        assertNotNull(event);
        assertEquals("203.0.113.5", event.sourceIp());
        assertEquals("root", event.username());
        assertFalse(event.success());
    }

    @Test
    void parsesAcceptedSshdLine() {
        LogParser parser = new LogParser();
        AuthEvent event = parser.parseLine(
                "Jun 14 08:10:00 host sshd[1300]: Accepted publickey for emmanuel from 192.0.2.44 port 22222 ssh2");
        assertNotNull(event);
        assertTrue(event.success());
        assertEquals("emmanuel", event.username());
    }

    @Test
    void parsesInvalidUserVariant() {
        LogParser parser = new LogParser();
        AuthEvent event = parser.parseLine(
                "Jun 14 03:22:01 host sshd[1234]: Failed password for invalid user admin123 from 203.0.113.5 port 51515 ssh2");
        assertNotNull(event);
        assertEquals("admin123", event.username());
    }

    @Test
    void ignoresUnrelatedLines() {
        LogParser parser = new LogParser();
        assertNull(parser.parseLine("this is not a log line at all"));
    }

    @Test
    void countsUnparsedLines() {
        LogParser parser = new LogParser();
        List<AuthEvent> events = parser.parseLines(List.of(
                "garbage line one",
                "Jun 14 03:22:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 51515 ssh2",
                "garbage line two"
        ));
        assertEquals(1, events.size());
        assertEquals(2, parser.getUnparsedLines());
    }
}
