package com.securegate.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securegate.config.SecurityProperties;
import com.securegate.model.AlertEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Appends one JSON object per line (JSON Lines) to the alert log and reads
 * the most recent entries back for the admin API.
 */
public class AlertLoggerService {

    private static final Logger log = LoggerFactory.getLogger(AlertLoggerService.class);
    private static final int TAIL_CHUNK = 8192;

    private final Path logFile;
    private final int maxPayloadLength;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public AlertLoggerService(SecurityProperties properties, Clock clock) {
        this.logFile = Paths.get(properties.getAlerts().getLogFile()).toAbsolutePath();
        this.maxPayloadLength = properties.getAlerts().getMaxPayloadLength();
        this.clock = clock;
        try {
            Path parent = logFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create alert log directory for " + logFile, e);
        }
        log.info("SecureGate alert log: {}", logFile);
    }

    public AlertEntry log(String ip, String attackType, String endpoint, String payload, String action) {
        AlertEntry entry = new AlertEntry(
                clock.instant().toString(), ip, attackType, endpoint, truncate(payload), action);
        try {
            // Jackson escapes control characters, so attacker-supplied newlines
            // cannot forge extra log lines.
            byte[] line = (mapper.writeValueAsString(entry) + "\n").getBytes(StandardCharsets.UTF_8);
            lock.writeLock().lock();
            try {
                Files.write(logFile, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
                        StandardOpenOption.WRITE);
            } finally {
                lock.writeLock().unlock();
            }
        } catch (IOException e) {
            log.error("Failed to write alert to {}", logFile, e);
        }
        return entry;
    }

    /** Returns up to {@code limit} alerts, newest first. */
    public List<AlertEntry> recent(int limit) {
        List<String> lines;
        lock.readLock().lock();
        try {
            lines = tailLines(limit);
        } catch (IOException e) {
            log.error("Failed to read alert log {}", logFile, e);
            return List.of();
        } finally {
            lock.readLock().unlock();
        }
        List<AlertEntry> result = new ArrayList<>(lines.size());
        for (String line : lines) {
            try {
                result.add(mapper.readValue(line, AlertEntry.class));
            } catch (IOException e) {
                log.debug("Skipping malformed alert line: {}", line);
            }
        }
        return result;
    }

    public Path getLogFile() {
        return logFile;
    }

    /** Reads the file backwards so cost is proportional to {@code limit}, not file size. */
    private List<String> tailLines(int limit) throws IOException {
        List<String> lines = new ArrayList<>();
        if (limit <= 0 || !Files.exists(logFile)) {
            return lines;
        }
        try (RandomAccessFile raf = new RandomAccessFile(logFile.toFile(), "r")) {
            long pos = raf.length();
            byte[] carry = new byte[0];
            while (pos > 0 && lines.size() < limit) {
                int size = (int) Math.min(TAIL_CHUNK, pos);
                pos -= size;
                byte[] chunk = new byte[size + carry.length];
                raf.seek(pos);
                raf.readFully(chunk, 0, size);
                System.arraycopy(carry, 0, chunk, size, carry.length);

                int end = chunk.length;
                for (int i = chunk.length - 1; i >= 0 && lines.size() < limit; i--) {
                    if (chunk[i] == '\n') {
                        addLine(lines, chunk, i + 1, end);
                        end = i;
                    }
                }
                carry = java.util.Arrays.copyOfRange(chunk, 0, end);
            }
            if (pos == 0 && carry.length > 0 && lines.size() < limit) {
                addLine(lines, carry, 0, carry.length);
            }
        }
        return lines;
    }

    private static void addLine(List<String> lines, byte[] buf, int from, int to) {
        String line = new String(buf, from, to - from, StandardCharsets.UTF_8).trim();
        if (!line.isEmpty()) {
            lines.add(line);
        }
    }

    private String truncate(String payload) {
        if (payload == null) {
            return "";
        }
        if (payload.length() <= maxPayloadLength) {
            return payload;
        }
        return payload.substring(0, maxPayloadLength) + "...[truncated]";
    }
}
