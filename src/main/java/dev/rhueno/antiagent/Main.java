package dev.rhueno.antiagent;

import java.util.List;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        boolean watch = has(args, "--watch");
        boolean legacy = has(args, "--legacy-blocker");
        State expected = expected(args);
        AntiAgent.Snapshot snapshot = legacy ? AntiAgent.installExperimentalLegacyBlocker() : AntiAgent.install();

        System.out.println("anti-java-agent");
        System.out.println("version -> " + AntiAgent.VERSION);
        System.out.println("java -> " + snapshot.javaVersion());
        System.out.println("vm -> " + snapshot.vmName());
        String pid = AgentCheck.pid();
        System.out.println("pid -> " + (pid == null ? "unknown" : pid));
        print(snapshot);

        if (expected != null && snapshot.state() != expected) {
            System.err.println("expected -> " + expected.name().toLowerCase());
            AntiAgent.shutdown();
            System.exit(2);
        }

        if (watch) {
            State previous = snapshot.state();
            List<String> findings = snapshot.findings();
            System.out.println("watching -> ctrl+c to stop");
            while (true) {
                Thread.sleep(500L);
                AntiAgent.Snapshot current = AntiAgent.snapshot();
                if (current.state() != previous || !current.findings().equals(findings)) {
                    System.out.println();
                    print(current);
                    previous = current.state();
                    findings = current.findings();
                }
            }
        }

        AntiAgent.shutdown();
    }

    private static boolean has(String[] args, String expected) {
        for (String argument : args) {
            if (expected.equals(argument)) {
                return true;
            }
        }
        return false;
    }

    private static State expected(String[] args) {
        String prefix = "--expect=";
        for (String argument : args) {
            if (argument != null && argument.startsWith(prefix)) {
                return State.valueOf(argument.substring(prefix.length()).trim().toUpperCase());
            }
        }
        return null;
    }

    private static void print(AntiAgent.Snapshot snapshot) {
        System.out.println();
        System.out.println("state -> " + snapshot.state().name().toLowerCase());
        System.out.println("attach disabled -> " + yesNo(snapshot.attachDisabled()));
        System.out.println("dynamic agent disabled -> " + yesNo(snapshot.dynamicAgentLoadingDisabled()));
        System.out.println("attach listener -> " + (snapshot.attachListenerObserved() ? "available" : "not observed"));
        System.out.println("jfr monitor -> " + (snapshot.jfrAgentMonitorActive() ? "active" : "unavailable"));
        if (snapshot.legacyInstrumentationBlockerSupported()) {
            String value = "disabled";
            if (snapshot.legacyInstrumentationBlockerEnabled()) {
                value = snapshot.legacyInstrumentationBlockerActive() ? "active" : "unavailable";
            }
            System.out.println("legacy blocker -> " + value);
        }
        System.out.println("integrity -> " + (snapshot.integrityIntact() ? "ok" : "failed"));
        System.out.println("proof -> " + Long.toUnsignedString(AntiAgent.proof(0x1337L), 16));

        if (snapshot.findings().isEmpty()) {
            System.out.println("findings -> none");
        } else {
            for (String finding : snapshot.findings()) {
                System.out.println("finding -> " + finding);
            }
        }

        System.out.println("recommended -> " + join(AntiAgent.recommendedJvmArguments()));
    }

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }

    private static String join(List<String> values) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                builder.append(' ');
            }
            builder.append(values.get(i));
        }
        return builder.toString();
    }
}
