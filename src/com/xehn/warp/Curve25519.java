package com.xehn.warp;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * X25519 (RFC 7748) implemented over BigInteger.
 *
 * <p>Only one keypair is derived per configuration, so the modular arithmetic is
 * nowhere near hot; correctness and readability beat constant-time speed here.
 */
public final class Curve25519 {

    public static final int SIZE = 32;

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A24 = BigInteger.valueOf(121665);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private Curve25519() {
    }

    /** A clamped private key, ready to hand to {@link #publicKey}. */
    public static byte[] randomPrivateKey() {
        byte[] k = new byte[SIZE];
        new SecureRandom().nextBytes(k);
        k[0] &= (byte) 248;
        k[31] &= (byte) 127;
        k[31] |= (byte) 64;
        return k;
    }

    /** {@code X25519(privateKey, 9)}: the public half of a WireGuard keypair. */
    public static byte[] publicKey(byte[] privateKey) {
        byte[] base = new byte[SIZE];
        base[0] = 9;
        return scalarMult(privateKey, base);
    }

    /** {@code X25519(scalar, point)}, both arguments and the result 32 bytes. */
    public static byte[] scalarMult(byte[] scalar, byte[] point) {
        if (scalar.length != SIZE || point.length != SIZE) {
            throw new IllegalArgumentException("X25519 inputs must be 32 bytes");
        }
        byte[] k = scalar.clone();
        k[0] &= (byte) 248;
        k[31] &= (byte) 127;
        k[31] |= (byte) 64;

        byte[] u = point.clone();
        u[31] &= (byte) 127;

        BigInteger x1 = decode(u);
        BigInteger x2 = BigInteger.ONE;
        BigInteger z2 = BigInteger.ZERO;
        BigInteger x3 = x1;
        BigInteger z3 = BigInteger.ONE;
        int swap = 0;

        for (int t = 254; t >= 0; t--) {
            int kt = (k[t >> 3] >> (t & 7)) & 1;
            swap ^= kt;
            if (swap != 0) {
                BigInteger tmp = x2;
                x2 = x3;
                x3 = tmp;
                tmp = z2;
                z2 = z3;
                z3 = tmp;
            }
            swap = kt;

            BigInteger a = x2.add(z2).mod(P);
            BigInteger aa = a.multiply(a).mod(P);
            BigInteger b = x2.subtract(z2).mod(P);
            BigInteger bb = b.multiply(b).mod(P);
            BigInteger e = aa.subtract(bb).mod(P);
            BigInteger c = x3.add(z3).mod(P);
            BigInteger d = x3.subtract(z3).mod(P);
            BigInteger da = d.multiply(a).mod(P);
            BigInteger cb = c.multiply(b).mod(P);
            BigInteger sum = da.add(cb).mod(P);
            BigInteger diff = da.subtract(cb).mod(P);

            x3 = sum.multiply(sum).mod(P);
            z3 = x1.multiply(diff.multiply(diff).mod(P)).mod(P);
            x2 = aa.multiply(bb).mod(P);
            z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P);
        }

        if (swap != 0) {
            BigInteger tmp = x2;
            x2 = x3;
            x3 = tmp;
            tmp = z2;
            z2 = z3;
            z3 = tmp;
        }

        BigInteger inverse = z2.modPow(P.subtract(TWO), P);
        return encode(x2.multiply(inverse).mod(P));
    }

    private static BigInteger decode(byte[] littleEndian) {
        byte[] be = new byte[SIZE];
        for (int i = 0; i < SIZE; i++) {
            be[i] = littleEndian[SIZE - 1 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] encode(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[SIZE];
        // BigInteger is big-endian and may carry a leading zero (or be shorter).
        int copied = Math.min(raw.length, SIZE);
        for (int i = 0; i < copied; i++) {
            out[i] = raw[raw.length - 1 - i];
        }
        return out;
    }
}
