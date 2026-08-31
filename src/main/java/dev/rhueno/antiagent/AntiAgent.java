package dev.rhueno.antiagent;

import java.lang.reflect.Method;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class AntiAgent {
    public static final String VERSION = "0.1.6";

    private static final AtomicBoolean INSTALLED = new AtomicBoolean();
    private static final AtomicBoolean RUNNING = new AtomicBoolean();
    private static final AtomicReference<Snapshot> SNAPSHOT = new AtomicReference<Snapshot>();
    private static final Integrity.Baseline BASELINE = Integrity.capture();
    private static volatile AgentEventMonitor agentEventMonitor;
    private static volatile Thread watchdog;
    private static volatile Boolean attachListenerAtInstall;
    private static volatile LegacyBlocker.Result legacyBlocker;
    private static volatile boolean legacyBlockerRequested;

    private AntiAgent() {
    }

    public static Snapshot install() {
        return install(false);
    }

    public static Snapshot installExperimentalLegacyBlocker() {
        return install(true);
    }

    private static Snapshot install(boolean enableLegacyBlocker) {
        if (INSTALLED.compareAndSet(false, true)) {
            RUNNING.set(true);
            legacyBlockerRequested = enableLegacyBlocker;
            legacyBlocker = enableLegacyBlocker ? LegacyBlocker.install() : LegacyBlocker.disabled();
            agentEventMonitor = AgentEventMonitor.start();
            refresh();
            watchdog = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (RUNNING.get()) {
                        try {
                            Thread.sleep(500L);
                        } catch (InterruptedException ignored) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                        refresh();
                    }
                }
            }, "anti-agent-watch");
            watchdog.setDaemon(true);
            watchdog.start();
        }
        return snapshot();
    }

    public static Snapshot snapshot() {
        Snapshot current = SNAPSHOT.get();
        if (current == null) {
            return install();
        }
        return current;
    }

    public static State state() {
        return snapshot().state();
    }

    public static boolean isTrusted() {
        return state() == State.TRUSTED;
    }

    public static boolean isCompromised() {
        return state() == State.COMPROMISED;
    }

    public static void requireUncompromised() {
        Snapshot current = snapshot();
        if (current.state() == State.COMPROMISED) {
            throw new IllegalStateException("instrumentation state is compromised");
        }
    }

    public static void requireTrusted() {
        Snapshot current = snapshot();
        if (current.state() != State.TRUSTED) {
            throw new IllegalStateException("instrumentation state is " + current.state().name().toLowerCase());
        }
    }

    public static long proof(long seed) {
        Snapshot current = snapshot();
        long value = mix(seed ^ BASELINE.token ^ current.environmentToken());
        if (current.state() != State.TRUSTED) {
            value = mix(value ^ 0xd6e8feb86659fd93L ^ ((long) current.state().ordinal() << 48));
        }
        return value;
    }

    public static List<String> recommendedJvmArguments() {
        return AgentCheck.recommendedArguments();
    }

    public static void shutdown() {
        RUNNING.set(false);
        Thread current = watchdog;
        if (current != null) {
            current.interrupt();
        }
        AgentEventMonitor monitor = agentEventMonitor;
        if (monitor != null) {
            monitor.close();
        }
    }

    private static void refresh() {
        AgentCheck.Result check = AgentCheck.inspect();
        Integrity.Result integrity = Integrity.verify(BASELINE);
        AgentEventMonitor monitor = agentEventMonitor;
        if (monitor != null) {
            monitor.poll();
        }
        boolean agentEvent = monitor != null && monitor.observed();
        boolean monitorActive = monitor != null && monitor.active();
        LegacyBlocker.Result blocker = legacyBlocker;
        boolean legacyBlockerSupported = blocker != null && blocker.supported;
        boolean legacyBlockerActive = blocker != null && blocker.active;
        boolean legacyBlockerEnabled = legacyBlockerRequested;
        Boolean initialAttachListener = attachListenerAtInstall;
        if (initialAttachListener == null) {
            initialAttachListener = Boolean.valueOf(check.attachListenerObserved);
            attachListenerAtInstall = initialAttachListener;
        }
        boolean attachListenerAppeared = !initialAttachListener.booleanValue() && check.attachListenerObserved;
        List<String> findings = new ArrayList<String>();
        findings.addAll(check.findings);

        if (attachListenerAppeared) {
            findings.add("attach listener appeared after protection initialization");
        }
        if (agentEvent) {
            findings.add("JFR agent event observed after protection initialization");
        }
        if (!integrity.intact && !integrity.unsupported) {
            findings.add("core class resource integrity changed");
        }
        if (legacyBlockerEnabled && legacyBlockerSupported && !legacyBlockerActive && !check.javaAgent && !check.nativeAgent) {
            findings.add("experimental legacy instrumentation blocker unavailable" + (blocker.failure == null ? "" : ": " + blocker.failure));
        }

        State state = State.TRUSTED;
        if (integrity.unsupported) {
            state = State.UNSUPPORTED;
        }
        if (check.dynamicAgentEnabled || check.selfAttachEnabled || attachListenerAppeared) {
            state = State.SUSPICIOUS;
        }
        if (check.javaAgent || check.nativeAgent || agentEvent || (!integrity.intact && !integrity.unsupported)) {
            state = State.COMPROMISED;
        }

        long environmentToken = BASELINE.token;
        environmentToken ^= check.attachDisabled ? 0x243f6a8885a308d3L : 0x13198a2e03707344L;
        environmentToken ^= check.dynamicAgentDisabled ? 0xa4093822299f31d0L : 0x082efa98ec4e6c89L;
        environmentToken ^= monitorActive ? 0x452821e638d01377L : 0xbe5466cf34e90c6cL;
        environmentToken ^= integrity.token;
        environmentToken ^= legacyBlockerEnabled ? 0x517cc1b727220a95L : 0x6c8e9cf570932bd5L;
        environmentToken ^= legacyBlockerActive ? 0x9e3779b97f4a7c15L : 0xc2b2ae3d27d4eb4fL;
        environmentToken = mix(environmentToken);

        SNAPSHOT.set(new Snapshot(
                state,
                System.getProperty("java.version", "unknown"),
                System.getProperty("java.vm.name", "unknown"),
                check.attachDisabled,
                check.dynamicAgentDisabled,
                check.attachListenerObserved,
                monitorActive,
                legacyBlockerSupported,
                legacyBlockerEnabled,
                legacyBlockerActive,
                integrity.intact,
                Collections.unmodifiableList(findings),
                environmentToken
        ));
    }

    private static long mix(long value) {
        value ^= value >>> 30;
        value *= 0xbf58476d1ce4e5b9L;
        value ^= value >>> 27;
        value *= 0x94d049bb133111ebL;
        value ^= value >>> 31;
        return value;
    }

    public static final class Snapshot {
        private final State state;
        private final String javaVersion;
        private final String vmName;
        private final boolean attachDisabled;
        private final boolean dynamicAgentLoadingDisabled;
        private final boolean attachListenerObserved;
        private final boolean jfrAgentMonitorActive;
        private final boolean legacyInstrumentationBlockerSupported;
        private final boolean legacyInstrumentationBlockerEnabled;
        private final boolean legacyInstrumentationBlockerActive;
        private final boolean integrityIntact;
        private final List<String> findings;
        private final long environmentToken;

        Snapshot(State state, String javaVersion, String vmName, boolean attachDisabled, boolean dynamicAgentLoadingDisabled, boolean attachListenerObserved, boolean jfrAgentMonitorActive, boolean legacyInstrumentationBlockerSupported, boolean legacyInstrumentationBlockerEnabled, boolean legacyInstrumentationBlockerActive, boolean integrityIntact, List<String> findings, long environmentToken) {
            this.state = state;
            this.javaVersion = javaVersion;
            this.vmName = vmName;
            this.attachDisabled = attachDisabled;
            this.dynamicAgentLoadingDisabled = dynamicAgentLoadingDisabled;
            this.attachListenerObserved = attachListenerObserved;
            this.jfrAgentMonitorActive = jfrAgentMonitorActive;
            this.legacyInstrumentationBlockerSupported = legacyInstrumentationBlockerSupported;
            this.legacyInstrumentationBlockerEnabled = legacyInstrumentationBlockerEnabled;
            this.legacyInstrumentationBlockerActive = legacyInstrumentationBlockerActive;
            this.integrityIntact = integrityIntact;
            this.findings = findings;
            this.environmentToken = environmentToken;
        }

        public State state() {
            return state;
        }

        public String javaVersion() {
            return javaVersion;
        }

        public String vmName() {
            return vmName;
        }

        public boolean attachDisabled() {
            return attachDisabled;
        }

        public boolean dynamicAgentLoadingDisabled() {
            return dynamicAgentLoadingDisabled;
        }

        public boolean attachListenerObserved() {
            return attachListenerObserved;
        }

        public boolean jfrAgentMonitorActive() {
            return jfrAgentMonitorActive;
        }

        public boolean legacyInstrumentationBlockerSupported() {
            return legacyInstrumentationBlockerSupported;
        }

        public boolean legacyInstrumentationBlockerEnabled() {
            return legacyInstrumentationBlockerEnabled;
        }

        public boolean legacyInstrumentationBlockerActive() {
            return legacyInstrumentationBlockerActive;
        }

        public boolean integrityIntact() {
            return integrityIntact;
        }

        public List<String> findings() {
            return findings;
        }

        long environmentToken() {
            return environmentToken;
        }
    }

    private static final class AgentEventMonitor {
        private final AtomicBoolean observed = new AtomicBoolean();
        private final AtomicBoolean active = new AtomicBoolean();
        private volatile long lastPoll;

        static AgentEventMonitor start() {
            AgentEventMonitor monitor = new AgentEventMonitor();
            monitor.active.set(supportsEvent("jdk.JavaAgent") || supportsEvent("jdk.NativeAgent"));
            return monitor;
        }

        boolean observed() {
            return observed.get();
        }

        boolean active() {
            return active.get();
        }

        void poll() {
            if (!active()) {
                return;
            }

            long now = System.currentTimeMillis();
            if (now - lastPoll < 2000L) {
                return;
            }
            lastPoll = now;

            Path path = null;
            Object recording = null;
            Object file = null;
            try {
                Class<?> recordingType = Class.forName("jdk.jfr.Recording");
                recording = recordingType.getConstructor().newInstance();
                Method enable = recordingType.getMethod("enable", String.class);
                if (supportsEvent("jdk.JavaAgent")) {
                    enable.invoke(recording, "jdk.JavaAgent");
                }
                if (supportsEvent("jdk.NativeAgent")) {
                    enable.invoke(recording, "jdk.NativeAgent");
                }
                recordingType.getMethod("start").invoke(recording);
                recordingType.getMethod("stop").invoke(recording);

                File temporary = File.createTempFile("anti-agent-", ".jfr");
                path = temporary.toPath();
                recordingType.getMethod("dump", Path.class).invoke(recording, path);
                recordingType.getMethod("close").invoke(recording);
                recording = null;

                Class<?> fileType = Class.forName("jdk.jfr.consumer.RecordingFile");
                file = fileType.getConstructor(Path.class).newInstance(path);
                Method hasMore = fileType.getMethod("hasMoreEvents");
                Method read = fileType.getMethod("readEvent");
                while (Boolean.TRUE.equals(hasMore.invoke(file))) {
                    Object event = read.invoke(file);
                    Object eventType = event.getClass().getMethod("getEventType").invoke(event);
                    String name = String.valueOf(eventType.getClass().getMethod("getName").invoke(eventType));
                    if (!"jdk.JavaAgent".equals(name) && !"jdk.NativeAgent".equals(name)) {
                        continue;
                    }
                    Object dynamic = event.getClass().getMethod("getValue", String.class).invoke(event, "dynamic");
                    if (Boolean.TRUE.equals(dynamic)) {
                        observed.set(true);
                    }
                }
                fileType.getMethod("close").invoke(file);
                file = null;
            } catch (Throwable ignored) {
            } finally {
                if (file != null) {
                    try {
                        file.getClass().getMethod("close").invoke(file);
                    } catch (Throwable ignored) {
                    }
                }
                if (recording != null) {
                    try {
                        recording.getClass().getMethod("close").invoke(recording);
                    } catch (Throwable ignored) {
                    }
                }
                if (path != null) {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Throwable ignored) {
                    }
                }
            }
        }

        void close() {
            active.set(false);
        }

        private static boolean supportsEvent(String expected) {
            try {
                Class<?> recorderType = Class.forName("jdk.jfr.FlightRecorder");
                Object recorder = recorderType.getMethod("getFlightRecorder").invoke(null);
                List<?> types = (List<?>) recorderType.getMethod("getEventTypes").invoke(recorder);
                for (Object type : types) {
                    String name = String.valueOf(type.getClass().getMethod("getName").invoke(type));
                    if (expected.equals(name)) {
                        return true;
                    }
                }
            } catch (Throwable ignored) {
            }
            return false;
        }
    }
}
