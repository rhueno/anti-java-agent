## anti-java-agent

a small java instrumentation hardening utility for detecting startup agents, runtime attachment and integrity changes.

### how does it work?

it checks vm arguments for java and native agents, observes attach state and tracks dynamic agent activity on supported runtimes.

java 8 includes an optional legacy blocker for late java agent loading. newer hotspot runtimes can be hardened further by disabling the attach mechanism and dynamic agent loading.

### build
