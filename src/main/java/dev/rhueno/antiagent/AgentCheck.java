package dev.rhueno.antiagent;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class AgentCheck {
    private AgentCheck() {
    }

    static Result inspect() {
        List<String> arguments = ManagementFactory.getRuntimeMXBean().getInputArguments();
        List<String> findings = new ArrayList<String>();
        boolean javaAgent = false;
        boolean nativeAgent = false;
        boolean dynamicAgentEnabled = false;
        boolean selfAttachEnabled = false;
        boolean attachDisabled = false;
        boolean dynamicAgentDisabled = false;
        boolean attachListenerRequested = false;

        for (String argument : arguments) {
            String value = argument == null ? "" : argument.trim();
            if (value.startsWith("-javaagent:")) {
                javaAgent = true;
                findings.add("startup javaagent detected: " + value);
            } else if (value.startsWith("-agentlib:") || value.startsWith("-agentpath:")) {
                nativeAgent = true;
                findings.add("startup native agent detected: " + value);
            }

            if ("-XX:+EnableDynamicAgentLoading".equals(value)) {
                dynamicAgentEnabled = true;
                findings.add("dynamic agent loading explicitly enabled");
            } else if ("-XX:-EnableDynamicAgentLoading".equals(value)) {
                dynamicAgentDisabled = true;
            } else if ("-XX:+DisableAttachMechanism".equals(value)) {
                attachDisabled = true;
            } else if ("-XX:+StartAttachListener".equals(value)) {
                attachListenerRequested = true;
                findings.add("attach listener explicitly requested at startup");
            }

            String selfAttachPrefix = "-Djdk.attach.allowAttachSelf=";
            if (value.startsWith(selfAttachPrefix) && Boolean.parseBoolean(value.substring(selfAttachPrefix.length()))) {
                selfAttachEnabled = true;
                findings.add("self attach explicitly enabled");
            }
        }

        return new Result(
                javaAgent,
                nativeAgent,
                dynamicAgentEnabled,
                selfAttachEnabled,
                attachDisabled,
                dynamicAgentDisabled,
                attachListenerRequested,
                observeAttachListener(),
                Collections.unmodifiableList(new ArrayList<String>(findings))
        );
    }

    static List<String> recommendedArguments() {
        List<String> result = new ArrayList<String>();
        result.add("-XX:+DisableAttachMechanism");
        if (javaMajor() >= 9) {
            result.add("-XX:-EnableDynamicAgentLoading");
        }
        return Collections.unmodifiableList(result);
    }

    static int javaMajor() {
        String version = System.getProperty("java.specification.version", "8");
        if (version.startsWith("1.")) {
            version = version.substring(2);
        }
        int dot = version.indexOf('.');
        if (dot >= 0) {
            version = version.substring(0, dot);
        }
        try {
            return Integer.parseInt(version);
        } catch (NumberFormatException ignored) {
            return 8;
        }
    }

    private static boolean observeAttachListener() {
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            String name = thread.getName();
            if (name != null && ("Attach Listener".equals(name) || name.startsWith("Attach Listener"))) {
                return true;
            }
        }

        if (!isUnixLike()) {
            return false;
        }

        String pid = pid();
        if (pid == null) {
            return false;
        }

        String temporary = System.getProperty("java.io.tmpdir");
        if (temporary != null && new File(temporary, ".java_pid" + pid).exists()) {
            return true;
        }
        return new File("/tmp", ".java_pid" + pid).exists();
    }

    private static String pid() {
        String name = ManagementFactory.getRuntimeMXBean().getName();
        int separator = name.indexOf('@');
        String value = separator < 0 ? name : name.substring(0, separator);
        if (value.isEmpty()) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return null;
            }
        }
        return value;
    }

    private static boolean isUnixLike() {
        String os = System.getProperty("os.name", "").toLowerCase();
        return os.contains("linux") || os.contains("mac") || os.contains("unix") || os.contains("bsd") || os.contains("aix");
    }

    static final class Result {
        final boolean javaAgent;
        final boolean nativeAgent;
        final boolean dynamicAgentEnabled;
        final boolean selfAttachEnabled;
        final boolean attachDisabled;
        final boolean dynamicAgentDisabled;
        final boolean attachListenerRequested;
        final boolean attachListenerObserved;
        final List<String> findings;

        Result(boolean javaAgent, boolean nativeAgent, boolean dynamicAgentEnabled, boolean selfAttachEnabled, boolean attachDisabled, boolean dynamicAgentDisabled, boolean attachListenerRequested, boolean attachListenerObserved, List<String> findings) {
            this.javaAgent = javaAgent;
            this.nativeAgent = nativeAgent;
            this.dynamicAgentEnabled = dynamicAgentEnabled;
            this.selfAttachEnabled = selfAttachEnabled;
            this.attachDisabled = attachDisabled;
            this.dynamicAgentDisabled = dynamicAgentDisabled;
            this.attachListenerRequested = attachListenerRequested;
            this.attachListenerObserved = attachListenerObserved;
            this.findings = findings;
        }
    }
}
