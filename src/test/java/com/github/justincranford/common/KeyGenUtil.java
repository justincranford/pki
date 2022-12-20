package com.github.justincranford.common;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyGenUtil {
	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

	public static KeyPairGenerator getKeyPairGenerator(final String algorithm, final Provider provider) throws NoSuchAlgorithmException {
        return (provider == null) ? KeyPairGenerator.getInstance(algorithm) : KeyPairGenerator.getInstance(algorithm, provider);
	}

	public static KeyGenerator getKeyGenerator(final String algorithm, final Provider provider) throws NoSuchAlgorithmException {
		return (provider == null) ? KeyGenerator.getInstance(algorithm) : KeyGenerator.getInstance(algorithm, provider);
	}

    public static KeyPair generateDhKeyPair(final int lengthBits, final Provider provider) throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyGenUtil.getKeyPairGenerator("DiffieHellman", provider);
        keyPairGenerator.initialize(lengthBits, SECURE_RANDOM);	// new DHGenParameterSpec(2048, 224)
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateRsaKeyPair(final int lengthBits, final Provider provider) throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyGenUtil.getKeyPairGenerator("RSA", provider);
        keyPairGenerator.initialize(lengthBits, SECURE_RANDOM);
        return keyPairGenerator.generateKeyPair();
    }

    // NIST EC P-256 => "secp256r1"
    // NIST EC P-384 => "secp384r1"
    // NIST EC P-521 => "secp521r1"
    public static KeyPair generateEcKeyPair(final String curve, final Provider provider) throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyGenUtil.getKeyPairGenerator("EC", provider);
        keyPairGenerator.initialize(new ECGenParameterSpec(curve), SECURE_RANDOM);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] getRandomBytes(final int bytesLength) throws Exception {
        final byte[] randomBytes = new byte[bytesLength];
        SECURE_RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }

	public static SecretKey generateSecretKey(final int lengthBits, final String algorithm, final Provider provider) throws Exception {
		final KeyGenerator keyGenerator = KeyGenUtil.getKeyGenerator(algorithm, provider);
		keyGenerator.init(lengthBits);
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
