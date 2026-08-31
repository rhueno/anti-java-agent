package dev.rhueno.antiagent;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

final class Integrity {
    private static final Class<?>[] CORE = new Class<?>[] {
            AntiAgent.class,
            State.class,
            AgentCheck.class,
            Integrity.class,
            LegacyBlocker.class
    };

    private Integrity() {
    }

    static Baseline capture() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Class<?> type : CORE) {
                digest.update(read(type));
            }
            byte[] hash = digest.digest();
            return new Baseline(hash, fold(hash));
        } catch (Exception exception) {
            return new Baseline(null, 0L);
        }
    }

    static Result verify(Baseline baseline) {
        if (baseline.hash == null) {
            return new Result(false, true, 0L);
        }
        Baseline current = capture();
        if (current.hash == null) {
            return new Result(false, true, 0L);
        }
        return new Result(Arrays.equals(baseline.hash, current.hash), false, current.token);
    }

    private static byte[] read(Class<?> type) throws Exception {
        String name = "/" + type.getName().replace('.', '/') + ".class";
        InputStream input = type.getResourceAsStream(name);
        if (input == null) {
            throw new IllegalStateException(name);
        }
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } finally {
            input.close();
        }
    }

    private static long fold(byte[] bytes) {
        long value = 0x6a09e667f3bcc909L;
        for (int i = 0; i < bytes.length; i++) {
            value ^= (long) (bytes[i] & 0xff) << ((i & 7) * 8);
            value = Long.rotateLeft(value * 0x9e3779b97f4a7c15L, 17);
        }
        return value;
    }

    static final class Baseline {
        final byte[] hash;
        final long token;

        Baseline(byte[] hash, long token) {
            this.hash = hash == null ? null : hash.clone();
            this.token = token;
        }
    }

    static final class Result {
        final boolean intact;
        final boolean unsupported;
        final long token;

        Result(boolean intact, boolean unsupported, long token) {
            this.intact = intact;
            this.unsupported = unsupported;
            this.token = token;
        }
    }
}
