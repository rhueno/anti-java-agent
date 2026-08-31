package dev.rhueno.antiagent;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.List;

final class LegacyBlocker {
    private static final String TARGET = "sun/instrument/InstrumentationImpl";

    private LegacyBlocker() {
    }

    static Result disabled() {
        return new Result(AgentCheck.javaMajor() == 8 && isHotSpot(), false, null);
    }

    static Result install() {
        if (AgentCheck.javaMajor() != 8 || !isHotSpot()) {
            return new Result(false, false, null);
        }
        if (hasStartupAgent(ManagementFactory.getRuntimeMXBean().getInputArguments())) {
            return new Result(true, false, "startup agent already initialized instrumentation");
        }

        try {
            Class<?> unsafeType = Class.forName("sun.misc.Unsafe");
            Field field = unsafeType.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            Object unsafe = field.get(null);
            Method defineClass = unsafeType.getMethod(
                    "defineClass",
                    String.class,
                    byte[].class,
                    int.class,
                    int.class,
                    ClassLoader.class,
                    ProtectionDomain.class
            );
            byte[] bytes = minimalClass(TARGET);
            defineClass.invoke(unsafe, TARGET.replace('/', '.'), bytes, 0, bytes.length, null, null);
            return new Result(true, true, null);
        } catch (InvocationTargetException error) {
            Throwable cause = error.getCause();
            return new Result(true, false, cause == null ? error.getClass().getName() : cause.getClass().getName());
        } catch (Throwable error) {
            return new Result(true, false, error.getClass().getName());
        }
    }

    private static boolean hasStartupAgent(List<String> arguments) {
        for (String argument : arguments) {
            String value = argument == null ? "" : argument.trim();
            if (value.startsWith("-javaagent:") || value.startsWith("-agentlib:") || value.startsWith("-agentpath:")) {
                return true;
            }
        }
        return false;
    }

    private static byte[] minimalClass(String internalName) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(output);
        data.writeInt(0xCAFEBABE);
        data.writeShort(0);
        data.writeShort(49);
        data.writeShort(5);
        writeUtf8(data, internalName);
        data.writeByte(7);
        data.writeShort(1);
        writeUtf8(data, "java/lang/Object");
        data.writeByte(7);
        data.writeShort(3);
        data.writeShort(0x0031);
        data.writeShort(2);
        data.writeShort(4);
        data.writeShort(0);
        data.writeShort(0);
        data.writeShort(0);
        data.writeShort(0);
        data.flush();
        return output.toByteArray();
    }

    private static void writeUtf8(DataOutputStream data, String value) throws Exception {
        data.writeByte(1);
        data.writeUTF(value);
    }

    private static boolean isHotSpot() {
        String name = System.getProperty("java.vm.name", "").toLowerCase();
        return name.contains("hotspot") || name.contains("openjdk");
    }

    static final class Result {
        final boolean supported;
        final boolean active;
        final String failure;

        Result(boolean supported, boolean active, String failure) {
            this.supported = supported;
            this.active = active;
            this.failure = failure;
        }
    }
}
