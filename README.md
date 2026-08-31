## anti-java-agent
A small utility for detecting and limiting Java instrumentation.

It detects startup Java/native agents, watches dynamic agent activity on supported JDKs, checks its packaged classes and exposes a protection state that can be used by applications or obfuscators.

This does not make native/JVMTI instrumentation impossible.

### Build

```
mvn clean package
```

### Run

```
java -jar target/anti-java-agent.jar
```

For HotSpot applications where attach is not needed:

```
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -jar app.jar
```

Java 8 has an optional legacy blocker:

```
java -jar target/anti-java-agent.jar --legacy-blocker
```
