package com.github.justincranford.common;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyGenUtil {
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static KeyPair generateKeyPair(final String algorithm, final Provider provider) throws Exception {
        final KeyPairGenerator subjectKeyPairGenerator;
        if (provider == null) {
            subjectKeyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            System.out.println("Found provider=" + subjectKeyPairGenerator.getProvider() + " for algorithm=" + subjectKeyPairGenerator.getAlgorithm());
        } else {
            subjectKeyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        }
        if (algorithm.equals("RSA")) {
            subjectKeyPairGenerator.initialize(2048); // NIST RSA-2048
        } else if (algorithm.equals("EC")) {
            subjectKeyPairGenerator.initialize(new ECGenParameterSpec("secp521r1")); // NIST EC P-521
        } else if (algorithm.equals("DiffieHellman")) {
            subjectKeyPairGenerator.initialize(2048);// new DHGenParameterSpec(2048, 256)); // NIST DH-2048
        } else {
            throw new Exception("Unsupported algorithm: " + algorithm);
        }
        return subjectKeyPairGenerator.generateKeyPair();
    }

    public static byte[] getRandomBytes(final int bytesLength) throws Exception {
        final byte[] randomBytes = new byte[bytesLength];
        SECURE_RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }

	public static SecretKey generateSecretKey(final int keySizeBytes, final String algorithm, final Provider provider) throws Exception {
		final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", provider);
		keyGenerator.init(keySizeBytes * 8);
		return keyGenerator.generateKey();
	}

	public static SecretKey generateSecretKey(final int lengthBytes, final String algorithm) throws Exception {
		final byte[] keyBytes = getRandomBytes(lengthBytes);
		return new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
	}

	public static SecretKey createSecretKey(final int lengthBytes, final String algorithm, final byte fillByte) {
		final byte[] keyBytes = createByteArray(lengthBytes, fillByte);
		return new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
	}

	public static byte[] createByteArray(final int lengthBytes, final byte fillByte) {
		final byte[] keyBytes = new byte[lengthBytes];
		Arrays.fill(keyBytes, fillByte);
		return keyBytes;
	}
}
