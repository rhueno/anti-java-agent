package dev.rhueno.antiagent;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

final class RuntimeEventMonitor {
    private static final String JAVA_AGENT = "jdk.JavaAgent";
    private static final String NATIVE_AGENT = "jdk.NativeAgent";

    private final AtomicBoolean active = new AtomicBoolean();
    private final AtomicBoolean agentObserved = new AtomicBoolean();
    private volatile Object recording;
    private volatile Class<?> recordingType;
    private volatile long lastPollNanos;

    static RuntimeEventMonitor start() {
        Set<String> available = availableEvents();
        Set<String> enabled = new HashSet<String>();
        addIfPresent(available, enabled, JAVA_AGENT);
        addIfPresent(available, enabled, NATIVE_AGENT);

        RuntimeEventMonitor monitor = new RuntimeEventMonitor();
        if (enabled.isEmpty()) {
            return monitor;
        }

        try {
            Class<?> type = Class.forName("jdk.jfr.Recording");
            Object recording = type.getConstructor().newInstance();
            Method enable = type.getMethod("enable", String.class);
            for (String event : enabled) {
                enable.invoke(recording, event);
            }
            configure(type, recording);
            type.getMethod("start").invoke(recording);
            monitor.recordingType = type;
            monitor.recording = recording;
            monitor.active.set(true);
        } catch (Throwable ignored) {
            monitor.closeRecording();
        }
        return monitor;
    }

    boolean active() {
        return active.get();
    }

    boolean agentObserved() {
        return agentObserved.get();
    }

    synchronized void poll() {
        if (!active()) {
            return;
        }

        long now = System.nanoTime();
        if (lastPollNanos != 0L && now - lastPollNanos < 2_000_000_000L) {
            return;
        }
        lastPollNanos = now;

        Path path = null;
        Object file = null;
        try {
            File temporary = File.createTempFile("anti-agent-", ".jfr");
            path = temporary.toPath();
            recordingType.getMethod("dump", Path.class).invoke(recording, path);

            Class<?> fileType = Class.forName("jdk.jfr.consumer.RecordingFile");
            file = fileType.getConstructor(Path.class).newInstance(path);
            Method hasMore = fileType.getMethod("hasMoreEvents");
            Method read = fileType.getMethod("readEvent");
            while (Boolean.TRUE.equals(hasMore.invoke(file))) {
                Object event = read.invoke(file);
                Object eventType = event.getClass().getMethod("getEventType").invoke(event);
                String name = String.valueOf(eventType.getClass().getMethod("getName").invoke(eventType));
                if (JAVA_AGENT.equals(name) || NATIVE_AGENT.equals(name)) {
                    agentObserved.set(true);
                }
            }

            fileType.getMethod("close").invoke(file);
            file = null;
        } catch (Throwable ignored) {
        } finally {
            closeFile(file);
            delete(path);
        }
    }

    synchronized void close() {
        active.set(false);
        closeRecording();
    }

    private void closeRecording() {
        Object current = recording;
        recording = null;
        recordingType = null;
        if (current == null) {
            return;
        }
        try {
            current.getClass().getMethod("close").invoke(current);
        } catch (Throwable ignored) {
        }
    }

    private static void closeFile(Object file) {
        if (file == null) {
            return;
        }
        try {
            file.getClass().getMethod("close").invoke(file);
        } catch (Throwable ignored) {
        }
    }

    private static void delete(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (Throwable ignored) {
        }
    }

    private static void configure(Class<?> type, Object recording) {
        try {
            type.getMethod("setMaxSize", long.class).invoke(recording, 8L * 1024L * 1024L);
        } catch (Throwable ignored) {
        }
        try {
            type.getMethod("setMaxAge", Duration.class).invoke(recording, Duration.ofSeconds(30L));
        } catch (Throwable ignored) {
        }
    }

    private static Set<String> availableEvents() {
        Set<String> result = new HashSet<String>();
        try {
            Class<?> recorderType = Class.forName("jdk.jfr.FlightRecorder");
            Object recorder = recorderType.getMethod("getFlightRecorder").invoke(null);
            List<?> types = (List<?>) recorderType.getMethod("getEventTypes").invoke(recorder);
            for (Object type : types) {
                String name = String.valueOf(type.getClass().getMethod("getName").invoke(type));
                result.add(name);
            }
        } catch (Throwable ignored) {
        }
        return result;
    }

    private static void addIfPresent(Set<String> available, Set<String> enabled, String name) {
        if (available.contains(name)) {
            enabled.add(name);
        }
    }
}
