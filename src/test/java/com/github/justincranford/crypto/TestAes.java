package com.github.justincranford.crypto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.Callable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.justincranford.common.KeyGenUtil;
import com.github.justincranford.common.StringUtil;

@DisplayName("Test AES")
class TestAes {
	private static final Logger LOGGER = LoggerFactory.getLogger(TestAes.class);
	private static final byte[] BYTE_ARRAY_EMPTY = new byte[] {};

	@BeforeAll static void beforeAll() {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);	// Register BC provider, required if making direct or indirect JCA/JCE calls to BC
	}

	@AfterAll static void afterAll() {
		Security.removeProvider("BC");	// Remove BC provider, so other test classes can add and remove BC provider
	}

	@Test void testAes() throws Exception {
		// GCM, CBC, ECB
		final Provider keyGeneratorProvider = Security.getProvider("BC");
		final SecretKey secretKey = KeyGenUtil.generateSecretKey(32, "AES", keyGeneratorProvider);
		final byte[] clearBytes = KeyGenUtil.getRandomBytes(16);

		// CBC only
		final IvParameterSpec ivParameterSpec = new IvParameterSpec(KeyGenUtil.getRandomBytes(16)); // AES/CBC IV should be 16-byes

		// GCM only
		final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, KeyGenUtil.getRandomBytes(12)); // AES/GCM IV should be 12-bytes
		final byte[] aadBytes = KeyGenUtil.getRandomBytes(100);

		final Provider cipherProvider = Security.getProvider("BC");
		this.aesTestHelper(clearBytes, secretKey, "AES/GCM/NoPadding",    cipherProvider, gcmParameterSpec, aadBytes);
		this.aesTestHelper(clearBytes, secretKey, "AES/GCM/NoPadding",    cipherProvider, gcmParameterSpec, BYTE_ARRAY_EMPTY);
		this.aesTestHelper(clearBytes, secretKey, "AES/GCM/NoPadding",    cipherProvider, gcmParameterSpec, null);
		this.aesTestHelper(clearBytes, secretKey, "AES/CBC/PKCS5Padding", cipherProvider, ivParameterSpec,  null);
		this.aesTestHelper(clearBytes, secretKey, "AES/ECB/PKCS5Padding", cipherProvider, null,             null);
	}

	private void aesTestHelper(
		final byte[] clearBytes,
		final SecretKey secretKey,
		final String cipherAlgorithm,
		final Provider cipherProvider,
		final Object optionalAlgorithmParameter,
		final byte[] optionalAadBytes
	) throws Exception {
		final byte[] encryptedBytes = doCipher(clearBytes,     secretKey, Cipher.ENCRYPT_MODE, cipherAlgorithm, cipherProvider, optionalAlgorithmParameter, optionalAadBytes);
		final byte[] decryptedBytes = doCipher(encryptedBytes, secretKey, Cipher.DECRYPT_MODE, cipherAlgorithm, cipherProvider, optionalAlgorithmParameter, optionalAadBytes);
		LOGGER.info("Clear     Bytes: " + StringUtil.hex(clearBytes));
		LOGGER.info("Encrypted Bytes: " + StringUtil.hex(encryptedBytes));
		LOGGER.info("Decrypted Bytes: " + StringUtil.hex(decryptedBytes));
		assertThat(decryptedBytes, is(equalTo(clearBytes)));
	}

	private byte[] doCipher(
		final byte[] clearBytes,					// clear bytes
		final SecretKey secretKey,					// AES key (128/192/256-bits, or 16/24/32-bytes)
		final int cipherMode,						// Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE
		final String cipherAlgorithm,				// AES/GCM/NoPadding, AES/CBC/PKCS5Padding, AES/ECB/PKCS5Padding
		final Provider cipherProvider,				// BC, SunJCE
		final Object optionalAlgorithmParameter,	// AlgorithmParameterSpec, AlgorithmParameters, GCMParameterSpec, IvParameterSpec
		final byte[] optionalAadBytes				// GCM only
	) throws Exception {
		final Cipher cipher = Cipher.getInstance(cipherAlgorithm, cipherProvider);
		if (optionalAlgorithmParameter instanceof AlgorithmParameterSpec algorithmParameterSpec) {
			cipher.init(cipherMode, secretKey, algorithmParameterSpec, KeyGenUtil.SECURE_RANDOM);
		} else if (optionalAlgorithmParameter instanceof AlgorithmParameters algorithmParameters) {
			cipher.init(cipherMode, secretKey, algorithmParameters, KeyGenUtil.SECURE_RANDOM);
		} else if (optionalAlgorithmParameter == null) {
			cipher.init(cipherMode, secretKey, KeyGenUtil.SECURE_RANDOM);
		} else {
			throw new InvalidParameterException("Unsupported parameter class " + optionalAlgorithmParameter.getClass().getCanonicalName());
		}
		if (optionalAadBytes != null) {
			cipher.updateAAD(optionalAadBytes);
		}
		return cipher.doFinal(clearBytes);
	}
}