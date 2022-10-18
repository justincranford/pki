package com.github.justincranford.common;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class KeyGenUtil {

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

    public static byte[] getRandomBytes(final int i, final String algorithm, final Provider provider) throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstance(algorithm, provider);
        final byte[] randomBytes = new byte[i];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }
}
