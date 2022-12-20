package com.github.justincranford.crypto;

import com.github.justincranford.common.KeyGenUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * TLS Key Exchange:
 *  Summary: ECDH => Pre-master Key -> Master Key (48-byte) -> Keys and IVs
 *
 * Roll your own TLS-like protocol.
 *  1. SESSION KDF KEY (ECDH, ADMIN PSK, RSA ENCRYPTED CLIENT KEY) => Analogous to TLS pre-master secret
 *  2. SESSION KDF IKM => Analogous to TLS label+seed
 *  3. SESSION KDF (ex: HKDF, not PBKDF2) => Analogous to TLS master secret
 *  3. SESSION (AES/CBC+HMAC or AES-GCM) => Analogous to TLS 2xAES and 2xHMAC session keys
 *  4. ENCRYPT
 *  5. SIGN => Analogous to TLS, but TLS does MAC first ENCRYPT second
 *  6. SEND => Any network/transport protocol (TCP/IP, UDP/IP, SMTP, USB drive, Courier, etc)
 *  7. VERIFY
 *  8. DECRYPT
 */
public class RollYourOwnTlsTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(RollYourOwnTlsTest.class);

    record SessionKeys(SecretKey aes, SecretKey hmac) {} // TODO Derive ID instead of random
    record ProtectedMessage(byte[] ciphertext, byte[] iv, byte[] signature) {} // TODO Derive IV instead of sending

    @Test void testEc() throws Exception {
        doSymmetricCrypto(sessionKdfKeyEcdh()); // EC Key agreement (521-bit)
    }

    @Test void testHmac() throws Exception {
        doSymmetricCrypto(KeyGenUtil.getRandomBytes(100)); // admin generated (800-bit)
    }

    @Test void testRsa() throws Exception {
        doSymmetricCrypto(sessionKdfKeyRsa()); // client generated, encrypted with server RSA public key (1024-bit, but wrapped in 128-bit)
    }

    private static void doSymmetricCrypto(final byte[] sessionKdfKey) throws Exception {
        final byte[] sessionKdfIkm = getSessionKdfIkm(); // concatenated via shared random from both
        final SessionKeys sessionKeys = getSessionAesAndHmacKeys(sessionKdfKey, sessionKdfIkm);
        final String cleartext = "Hello World";
        final ProtectedMessage protectedMessage = encryptAndSignBody(sessionKeys, cleartext);
        final String decrypted = verifyAndDecryptBody(sessionKeys, protectedMessage);
        assertThat(decrypted, is(equalTo(cleartext)));
    }

    private static byte[] sessionKdfKeyEcdh() throws Exception {
        final Provider keyPairGeneratorProvider = Security.getProvider("SunEC"); // for algorithm=secp521r1
        final Provider keyAgreementProvider = Security.getProvider("SunEC"); // for algorithm=ECDH

        // Client & server generate ephemeral EC-P521 key pairs for deriving a 521-bit KDF key
        final KeyPair clientKeyPair = KeyGenUtil.generateKeyPair("EC", keyPairGeneratorProvider);
        final KeyPair serverKeyPair = KeyGenUtil.generateKeyPair("EC", keyPairGeneratorProvider);
        assertThat(clientKeyPair.getPrivate(), is(not(equalTo(serverKeyPair.getPrivate()))));
        assertThat(clientKeyPair.getPublic(), is(not(equalTo(serverKeyPair.getPublic()))));

        // Client KDF key = Server private key + Client public key
        final KeyAgreement clientKeyAgreement = KeyAgreement.getInstance("ECDH", keyAgreementProvider);
        clientKeyAgreement.init(clientKeyPair.getPrivate());
        clientKeyAgreement.doPhase(serverKeyPair.getPublic(), true);
        final byte[] clientKeyAgreementSecret = clientKeyAgreement.generateSecret();
        LOGGER.info("Client KeyAgreement Secret [{}b,{}B]: 0x{}", 8 * clientKeyAgreementSecret.length, clientKeyAgreementSecret.length, HexFormat.of().withUpperCase().formatHex(clientKeyAgreementSecret));

        // Server KDF key = Client private key + Server public key
        final KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("ECDH", keyAgreementProvider);
        serverKeyAgreement.init(serverKeyPair.getPrivate());
        serverKeyAgreement.doPhase(clientKeyPair.getPublic(), true);
        final byte[] serverKeyAgreementSecret = serverKeyAgreement.generateSecret();
        LOGGER.info("Server KeyAgreement Secret [{}b,{}B]: 0x{}", 8 * serverKeyAgreementSecret.length, serverKeyAgreementSecret.length, HexFormat.of().withUpperCase().formatHex(clientKeyAgreementSecret));

        // Client KDF key == Server KDF key
        assertThat(clientKeyAgreementSecret, is(equalTo(serverKeyAgreementSecret)));
        return serverKeyAgreementSecret;
    }

    private static byte[] sessionKdfKeyRsa() throws Exception {
        // Server has an RSA key pair, and shares the RSA public key with the client
        final KeyPair serverKeyPair = KeyGenUtil.generateKeyPair("RSA", null);

        // Client generates a KDF key
        final byte[] kdfKey = KeyGenUtil.getRandomBytes(80);

        // Client encrypts the KDF key with the server RSA public key (2048-bit => 256-bytes => 128-bytes max plus pad)
        final Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, serverKeyPair.getPublic());
        final byte[] ciphertext = encryptCipher.doFinal(kdfKey);

        final Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
        final byte[] decrypted = decryptCipher.doFinal(ciphertext);

        // Decrypted == kdfKey
        assertThat(Arrays.equals(kdfKey, decrypted), is(true));
        return decrypted;
    }

    private static byte[] getSessionKdfIkm() throws Exception {
        // Client & server generate input key material to share and combine
        final byte[] clientSalt = KeyGenUtil.getRandomBytes(40);
        final byte[] serverSalt = KeyGenUtil.getRandomBytes(40);
        assertThat(clientSalt, is(not(equalTo(serverSalt))));

        // Client input key material = server salt + client salt
        final byte[] clientKeyMaterial = new byte[serverSalt.length + clientSalt.length];
        System.arraycopy(serverSalt, 0, clientKeyMaterial, 0, serverSalt.length);
        System.arraycopy(clientSalt, 0, clientKeyMaterial, serverSalt.length, clientSalt.length);

        // Server input key material = server salt + client salt // TODO Prepend label "master secret"
        final byte[] serverKeyMaterial = new byte[serverSalt.length + clientSalt.length];
        System.arraycopy(serverSalt, 0, serverKeyMaterial, 0, serverSalt.length);
        System.arraycopy(clientSalt, 0, serverKeyMaterial, serverSalt.length, clientSalt.length);

        // Client input key material == Server input key material
        assertThat(clientKeyMaterial, is(equalTo(serverKeyMaterial)));
        return serverKeyMaterial;
    }

    private static SessionKeys getSessionAesAndHmacKeys(byte[] sessionKdfKey, byte[] sessionKdfIkm) throws Exception {
        // TODO Use pre-master key to derive master key first, then use master key to derive AES+HMAC+IV

        // Client uses KDF key and KDF input key material to derive a session key (= AES-256-CBC + HmacSHA256)
        final Mac clientMac = Mac.getInstance("HmacSHA512"); // 512-bit, 64-bytes
        clientMac.init(new SecretKeySpec(sessionKdfKey, "HmacSHA512"));
        final byte[] clientMacSecret = clientMac.doFinal(sessionKdfIkm);
        final SecretKey clientSessionAesKey = new SecretKeySpec(clientMacSecret, 0, 32, "AES"); // 256-bit
        final SecretKey clientSessionMacKey = new SecretKeySpec(clientMacSecret, 32, 32, "AES"); // 256-bit

        // Server uses KDF key and KDF input key material to derive a session key (= AES-256-CBC + HmacSHA256)
        final Mac serverMac = Mac.getInstance("HmacSHA512"); // 512-bit, 64-bytes
        serverMac.init(new SecretKeySpec(sessionKdfKey, "HmacSHA512"));
        final byte[] serverMacSecret = serverMac.doFinal(sessionKdfIkm);
        final SecretKey serverSessionAesKey = new SecretKeySpec(serverMacSecret, 0, 32, "AES");
        final SecretKey serverSessionMacKey = new SecretKeySpec(serverMacSecret, 32, 32, "AES");

        // Verify both sides derive the same session key (= AES-256-CBC + HmacSHA256)
        assertThat(clientSessionAesKey, is(equalTo(serverSessionAesKey)));
        assertThat(clientSessionMacKey, is(equalTo(serverSessionMacKey)));
        return new SessionKeys(serverSessionAesKey, serverSessionMacKey); // TODO Derive IV
    }

    private static ProtectedMessage encryptAndSignBody(SessionKeys sessionKeys, String clientClearRequest) throws Exception {
        // Client generates a clear request
        LOGGER.info("Client Clear Request [{}b,{}B]: {}", 8 * clientClearRequest.length(), clientClearRequest.length(), clientClearRequest);

        // Client encrypts the clear request using the AES-256-CBC part of the session key
        final byte[] clientAesCbcIv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(clientAesCbcIv);
        final Cipher clientAesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        clientAesCbcCipher.init(Cipher.ENCRYPT_MODE, sessionKeys.aes(), new IvParameterSpec(clientAesCbcIv));
        final byte[] clientEncryptedRequest = clientAesCbcCipher.doFinal(clientClearRequest.getBytes(StandardCharsets.UTF_8));

        // CLIENT SIGNS THE ENCRYPTED REQUEST

        // Client signs the encrypted request using the HmacSha256 part of the session key
        final Mac clientRequestMac = Mac.getInstance("HmacSHA256");
        clientRequestMac.init(sessionKeys.hmac());
        final byte[] clientRequestSignature = clientRequestMac.doFinal(clientEncryptedRequest);

        // CLIENT SENDS THE ENCRYPTED+SIGNED REQUEST

        // Client sends the signature, encrypted message, and encryption IV to the server over unsecure medium
        final byte[] receivedRequestSignature = clientRequestSignature;
        final byte[] receivedEncryptedRequest = clientEncryptedRequest;
        final byte[] receivedAesCbcIv = clientAesCbcIv;
        LOGGER.info("Received Signature [{}b,{}B]: {}", 8 * receivedRequestSignature.length, receivedRequestSignature.length, receivedRequestSignature);
        LOGGER.info("Received Encrypted Request [{}b,{}B]: {}", 8 * receivedEncryptedRequest.length, receivedEncryptedRequest.length, receivedEncryptedRequest);
        LOGGER.info("Received AES CBC IV [{}b,{}B]: {}", 8 * receivedAesCbcIv.length, receivedAesCbcIv.length, receivedAesCbcIv);
        return new ProtectedMessage(receivedEncryptedRequest, receivedAesCbcIv, receivedRequestSignature);
    }

    private static String verifyAndDecryptBody(SessionKeys sessionKeys, ProtectedMessage payload) throws Exception {
        // Server verifies the signature using the HmacSha256 part of the session key
        final Mac serverRequestMac = Mac.getInstance("HmacSHA256");
        serverRequestMac.init(sessionKeys.hmac());
        final byte[] serverRequestSignature = serverRequestMac.doFinal(payload.ciphertext());
        assertThat(serverRequestSignature, is(equalTo(payload.signature())));

        // SERVER DECRYPTS THE REQUEST

        // Server uses the AES-256-CBC part of the session key, and the clear IV, to decrypt the client request
        final Cipher serverAesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        serverAesCbcCipher.init(Cipher.DECRYPT_MODE, sessionKeys.aes(), new IvParameterSpec(payload.iv()));
        final byte[] serverClearRequestBytes = serverAesCbcCipher.doFinal(payload.ciphertext());
        final String serverClearRequest = new String(serverClearRequestBytes, StandardCharsets.UTF_8);
        LOGGER.info("Server Decrypted Request [{}b,{}B]: {}", 8 * serverClearRequest.length(), serverClearRequest.length(), serverClearRequest);
        return serverClearRequest;
    }

    /**
     * TLS :
     *   premaster_secret = ECDH/RSA(pre_master_secret)                                        // derived, random, PSK
     *   master_secret = PRF(pre_master_secret,                                                // derived, random, PSK
     *                       "master secret",                                                  // label
     *                       ClientHello.random + ServerHello.random)                          // seed
     *   key_block = PRF(SecurityParameters.master_secret,                                     // always derived
     *                   "key expansion",                                                      // label
     *                   SecurityParameters.server_random + SecurityParameters.client_random); // seed
     *
     *   client_write_MAC_key[SecurityParameters.mac_key_length] // empty for AES-GCM
     *   server_write_MAC_key[SecurityParameters.mac_key_length] // empty for AES-GCM
     *   client_write_key[SecurityParameters.enc_key_length]
     *   server_write_key[SecurityParameters.enc_key_length]
     *   client_write_IV[SecurityParameters.fixed_iv_length]
     *   server_write_IV[SecurityParameters.fixed_iv_length]
     */
}