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
import java.security.*;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class KeyAgreementTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyAgreementTest.class);

    /**
     * Security components:
     *  1. Session Key: KDF(PreKey,ClientIKM & ServerIKM), PreKey can be obtained via KA, PSK, or Client-generated.
     *  2. Confidentiality: First chunk of session key is used as AES key (ex: AES-256-CBC, AES-256-GCM).
     *  3. Integrity: Second chunk of session key is used as HMAC key (ex: HmacSHA256).
     *  4. Authentication: Not required in TLS 1.2.
     *
     * Types of authentication:
     *  1. Central trust (ex: PKI), central public keys are trusted (aka public CA certificates)
     *  2. Group trust (ex: PGP), trusted public key is a seed seeds to trust other public keys (aka 2nd level connections)
     *  3. Single trust (ex: SSH), individual public keys are trusted (aka 1st level connections)
     *
     * @throws Exception Error if something goes wrong
     */
    @Test
    void testClientServerRollYourOwnTls() throws Exception {
        final Provider keyPairGeneratorProvider = Security.getProvider("SunEC"); // for algorithm=secp521r1
        final Provider keyAgreementProvider = Security.getProvider("SunEC"); // for algorithm=ECDH
        final Provider secureRandomProvider = Security.getProvider("SUN"); // for algorithm=SHA1PRNG

        // Client generates ephemeral EC-P521 key pairs for deriving a 521-bit pre-master secret
        final KeyPair clientKeyPair = KeyGenUtil.generateKeyPair("EC", keyPairGeneratorProvider);
        final PublicKey clientPublicKey = clientKeyPair.getPublic(); // send to server
        final PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
        // Client generates ephemeral salt to share with the server
        final SecureRandom secureRandomClient = SecureRandom.getInstance("SHA1PRNG", secureRandomProvider);
        final byte[] clientSalt = new byte[32];
        secureRandomClient.nextBytes(clientSalt); // send to server

        // Server generates ephemeral EC-P521 key pairs for deriving a 521-bit pre-master secret
        final KeyPair serverKeyPair = KeyGenUtil.generateKeyPair("EC", keyPairGeneratorProvider);
        final PublicKey serverPublicKey = serverKeyPair.getPublic();
        final PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        // Server generates ephemeral salt to share with the client
        final byte[] serverSalt = KeyGenUtil.getRandomBytes("SHA1PRNG", secureRandomProvider);

        // Confirm key pair and salts are different
        assertThat(clientPrivateKey, is(not(equalTo(serverPrivateKey))));
        assertThat(clientPublicKey, is(not(equalTo(serverPublicKey))));
        assertThat(clientSalt, is(not(equalTo(serverSalt))));

        // Client pre-master secret = Server private key + Client public key
        final KeyAgreement clientKeyAgreement = KeyAgreement.getInstance("ECDH", keyAgreementProvider);
        clientKeyAgreement.init(clientPrivateKey);
        clientKeyAgreement.doPhase(serverPublicKey, true);
        final byte[] clientKeyAgreementSecret = clientKeyAgreement.generateSecret();
        LOGGER.info("Client KeyAgreement Secret [{}b,{}B]: 0x{}", 8 * clientKeyAgreementSecret.length, clientKeyAgreementSecret.length, HexFormat.of().withUpperCase().formatHex(clientKeyAgreementSecret));

        // Server pre-master secret = Client private key + Server public key
        final KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("ECDH", keyAgreementProvider);
        serverKeyAgreement.init(serverPrivateKey);
        serverKeyAgreement.doPhase(clientPublicKey, true);
        final byte[] serverKeyAgreementSecret = serverKeyAgreement.generateSecret();
        LOGGER.info("Server KeyAgreement Secret [{}b,{}B]: 0x{}", 8 * serverKeyAgreementSecret.length, serverKeyAgreementSecret.length, HexFormat.of().withUpperCase().formatHex(clientKeyAgreementSecret));

        // Client input key material = server salt + client salt
        final byte[] clientKeyMaterial = new byte[serverSalt.length + clientSalt.length];
        System.arraycopy(serverSalt, 0, clientKeyMaterial, 0, serverSalt.length);
        System.arraycopy(clientSalt, 0, clientKeyMaterial, serverSalt.length, clientSalt.length);

        // Server input key material = server salt + client salt
        final byte[] serverKeyMaterial = new byte[serverSalt.length + clientSalt.length];
        System.arraycopy(serverSalt, 0, serverKeyMaterial, 0, serverSalt.length);
        System.arraycopy(clientSalt, 0, serverKeyMaterial, serverSalt.length, clientSalt.length);

        // Client pre-master secret == Server pre-master secret
        assertThat(clientKeyAgreementSecret, is(equalTo(serverKeyAgreementSecret)));
        // Client input key material == Server input key material
        assertThat(clientKeyMaterial, is(equalTo(serverKeyMaterial)));
        // At this point, both sides have the same pre-master secret (ex: EC-P521 => 521-bit derived secret) and key material

        // Client uses pre-master secret and input key material to derive a session key (= AES-256-CBC + HmacSHA256)
        final Mac clientMac = Mac.getInstance("HmacSHA512"); // 512-bit, 64-bytes
        clientMac.init(new SecretKeySpec(clientKeyAgreementSecret, "HmacSHA512"));
        final byte[] clientMacSecret = clientMac.doFinal(clientKeyMaterial);
        final SecretKey clientSessionAesKey = new SecretKeySpec(clientMacSecret, 0, 32, "AES"); // 256-bit
        final SecretKey clientSessionMacKey = new SecretKeySpec(clientMacSecret, 32, 32, "AES"); // 256-bit

        // Server uses pre-master secret and session salts to derive a session key (= AES-256-CBC + HmacSHA256)
        final Mac serverMac = Mac.getInstance("HmacSHA512"); // 512-bit, 64-bytes
        serverMac.init(new SecretKeySpec(clientKeyAgreementSecret, "HmacSHA512"));
        final byte[] serverMacSecret = serverMac.doFinal(serverKeyMaterial);
        final SecretKey serverSessionAesKey = new SecretKeySpec(serverMacSecret, 0, 32, "AES");
        final SecretKey serverSessionMacKey = new SecretKeySpec(serverMacSecret, 32, 32, "AES");

        // Verify both sides derive the same session key (= AES-256-CBC + HmacSHA256)
        assertThat(clientSessionAesKey, is(equalTo(serverSessionAesKey)));
        assertThat(clientSessionMacKey, is(equalTo(serverSessionMacKey)));

        // Client generates a clear request
        final String clientClearRequest = "Hello World";
        LOGGER.info("Client Clear Request [{}b,{}B]: {}", 8 * clientClearRequest.length(), clientClearRequest.length(), clientClearRequest);

        // Client encrypts the clear request using the AES-256-CBC part of the session key
        final byte[] clientAesCbcIv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(clientAesCbcIv);
        final Cipher clientAesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        clientAesCbcCipher.init(Cipher.ENCRYPT_MODE, clientSessionAesKey, new IvParameterSpec(clientAesCbcIv));
        final byte[] clientEncryptedRequest = clientAesCbcCipher.doFinal(clientClearRequest.getBytes(StandardCharsets.UTF_8));

        // Client signs the encrypted request using the HmacSha256 part of the session key
        final Mac clientRequestMac = Mac.getInstance("HmacSHA256");
        clientRequestMac.init(clientSessionMacKey);
        final byte[] clientRequestSignature = clientMac.doFinal(clientEncryptedRequest);

        // Client sends the signature, encrypted message, and encryption IV to the server over unsecure medium
        final byte[] receivedRequestSignature = clientRequestSignature;
        final byte[] receivedEncryptedRequest = clientEncryptedRequest;
        final byte[] receivedAesCbcIv = clientAesCbcIv;
        LOGGER.info("Received Signature [{}b,{}B]: {}", 8 * receivedRequestSignature.length, receivedRequestSignature.length, receivedRequestSignature);
        LOGGER.info("Received Encrypted Request [{}b,{}B]: {}", 8 * receivedEncryptedRequest.length, receivedEncryptedRequest.length, receivedEncryptedRequest);
        LOGGER.info("Received AES CBC IV [{}b,{}B]: {}", 8 * receivedAesCbcIv.length, receivedAesCbcIv.length, receivedAesCbcIv);

        // Server verifies the signature using the HmacSha256 part of the session key
        final Mac serverRequestMac = Mac.getInstance("HmacSHA256");
        serverRequestMac.init(serverSessionMacKey);
        final byte[] serverRequestSignature = clientMac.doFinal(receivedEncryptedRequest);
        assertThat(serverRequestSignature, is(equalTo(receivedRequestSignature)));

        // Server uses the AES-256-CBC part of the session key, and the clear IV, to decrypt the client request
        final Cipher serverAesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        serverAesCbcCipher.init(Cipher.DECRYPT_MODE, serverSessionAesKey, new IvParameterSpec(receivedAesCbcIv));
        final byte[] serverClearRequestBytes = serverAesCbcCipher.doFinal(receivedEncryptedRequest);
        final String serverClearRequest = new String(serverClearRequestBytes, StandardCharsets.UTF_8);
        LOGGER.info("Server Decrypted Request [{}b,{}B]: {}", 8 * serverClearRequest.length(), serverClearRequest.length(), serverClearRequest);

        // Verify the server decrypted the original clear client request
        assertThat(serverClearRequest, is(equalTo(clientClearRequest)));
    }
}