## anti-java-agent

a small java instrumentation hardening utility for detecting startup agents, runtime attachment, class transformation activity and resource tampering.

### how does it work?

it checks vm arguments for [java agents](https://docs.oracle.com/javase/7/docs/api/java/lang/instrument/package-summary.html) and native agents, observes attach state and keeps a JFR recording open on supported runtimes so short-lived agent, redefine and retransform events are not lost between polling windows.

resource integrity hashes the packaged class resources. it does not claim to read the JVM's currently loaded transformed bytecode. runtime class changes are tracked separately through JFR redefinition and retransformation events when those events are available.

java 8 includes an optional legacy blocker for late java agent loading. newer hotspot runtimes can be hardened further by disabling the attach mechanism and dynamic agent loading.
