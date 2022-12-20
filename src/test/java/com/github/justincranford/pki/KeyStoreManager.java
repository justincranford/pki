package com.github.justincranford.pki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AuthProvider;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.justincranford.common.KeyGenUtil;
import com.github.justincranford.common.PemUtil;
import com.github.justincranford.common.SecureRandomUtil;

// Root CA, Sub CA, Cross-cert, Client/Server End Entity, Client/Server self-signed, etc
public record KeyStoreManager(
		KeyStore keyStore,				// PKCS12, PKCS11
		Provider keyStoreProvider,		// SunJSSE, SunPKCS11
		char[] keyStorePassword,		// PKCS12 file integrity, PKCS11 HSM slot login
		KeyStore.PrivateKeyEntry entry,	// PKCS12 in-memory private key, PKCS11 in-HSM private key identifier
		String entryAlias,				// PrivateKeyEntry alias
		char[] entryPassword,			// PrivateKeyEntry password (PKCS12 entry encryption, PKCS11 null)
		Provider entrySignatureProvider	// SunRsaSign, SunEC, SunPKCS11
	) {
	private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreManager.class);

	/**
	 * Create any entity such as root CA, sub CA, cross-cert, RA, CA-signed end-entity, self-signed end-entity, etc
	 * @param issuerKeyStoreManager Null if self-signed, otherwise it is a non-null issuer 
	 * @param subjectRelativeName Subject RDN, where Subject DN will be SubjectRDN,IssuerDN or SubjectRDN (self-issued)
	 * @param subjectKeyPairAlgorithm RSA or EC 
	 * @param subjectKeyStorePassword PKCS#12 or PKCS11 keystore password
	 * @param subjectKeyStoreEntryPassword PKCS#12 entry password, or null for PKCS11 entries
	 * @param subjectExtensions Array of extensions to add to the subject certificate
	 * @param subjectSunpkcs11Conf Null for PKCS#12, non-null file path for PKCS#11
	 * @return Entity object containing links to the KeyStore, KeysStore provider, password, alias, entry password, and signature provider
	 * @throws Exception Unexpected error
	 */
	public static KeyStoreManager create(
		final KeyStoreManager issuerKeyStoreManager,	// null for self-signed
		final String subjectRelativeName,				// "CN=Client End Entity+serial=123";
		final String subjectKeyPairAlgorithm,			// "EC";
		final char[] subjectKeyStorePassword,			// "Client".toCharArray();
		final char[] subjectKeyStoreEntryPassword,		// "Client".toCharArray();
		final Extension[] subjectExtensions,			// BasicConstraints, KeyUsage, ExtendedKeyUsage, GeneralNames, etc
		final String subjectSunpkcs11Conf				// SUNPKCS11_CLIENT_END_ENTITY_CONF resolved file path
	) throws Exception {
		final Provider subjectKeyPairGeneratorProvider;	// SunPKCS11, SunRsaSign/SunEC
		final KeyPair  subjectKeyPair;					// RSA or EC; generated and stored in-memory or in-hardware 
		final Provider subjectKeyStoreProvider;			// SunPKCS11, SunPKCS11
		final KeyStore subjectKeyStore;					// PKCS11, PKCS12
		final Provider subjectSignatureProvider;
		if (subjectSunpkcs11Conf == null) {
			subjectSignatureProvider = subjectKeyPairGeneratorProvider = subjectKeyPairAlgorithm.equals("RSA") ? Security.getProvider("SunRsaSign") : Security.getProvider("SunEC");
			subjectKeyPair = subjectKeyPairAlgorithm.equals("RSA") ? KeyGenUtil.generateRsaKeyPair(2048, subjectKeyPairGeneratorProvider) : KeyGenUtil.generateEcKeyPair("secp256r1", subjectKeyPairGeneratorProvider);
			subjectKeyStoreProvider = Security.getProvider("SunJSSE");
			subjectKeyStore = KeyStore.getInstance("PKCS12", subjectKeyStoreProvider);
			subjectKeyStore.load(null, null);
		} else {
			final AuthProvider authProvider = (AuthProvider) Security.getProvider("SunPKCS11").configure(subjectSunpkcs11Conf); // SunPKCS11 RSA||EC
			final CallbackHandler loginCallbackHandler = new ProviderCallbackHandler(subjectKeyStorePassword); // PKCS11 C_Login pwd for Provider=SunPKCS11 and KeyStore=PKCS11
			authProvider.login(null, loginCallbackHandler);
			Security.addProvider(authProvider); // register AuthProvider so JCA/JCE API calls can use it for crypto operations like KeyPairGenerator
			subjectSignatureProvider = subjectKeyPairGeneratorProvider = authProvider;
			subjectKeyPair = subjectKeyPairAlgorithm.equals("RSA") ? KeyGenUtil.generateRsaKeyPair(2048, authProvider) : KeyGenUtil.generateEcKeyPair("secp256r1", authProvider);
			subjectKeyStoreProvider = authProvider;
			subjectKeyStore = KeyStore.Builder.newInstance("PKCS11", authProvider, new KeyStore.CallbackHandlerProtection(loginCallbackHandler)).getKeyStore(); // Keyproxy for network auto-reconnects
			KeyStoreManager.printKeyStoreEntryAliases(subjectKeyStore, authProvider);
		}

		final Provider issuerSignatureProvider;
		final PrivateKey issuerPrivateKey;
		final String issuerSignatureAlgorithm;
		final String issuerName;
		final String subjectName;
		if (issuerKeyStoreManager == null) {
			issuerSignatureProvider = subjectSignatureProvider;
			issuerPrivateKey = subjectKeyPair.getPrivate();
			issuerSignatureAlgorithm = subjectKeyPairAlgorithm.equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
			subjectName = issuerName = subjectRelativeName;
		} else {
			issuerSignatureProvider = issuerKeyStoreManager.entrySignatureProvider;
			issuerPrivateKey = issuerKeyStoreManager.entry.getPrivateKey();
			issuerSignatureAlgorithm = issuerPrivateKey.getAlgorithm().equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
			issuerName = ((X509Certificate)issuerKeyStoreManager.entry.getCertificate()).getSubjectX500Principal().getName(X500Principal.RFC2253);
			subjectName = subjectRelativeName + "," + issuerName;
		}

		final Certificate subjectCertificate = CertUtil.createCert(
			Date.from(ZonedDateTime.of(1970, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()),
			Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
			new BigInteger(159, SecureRandomUtil.DEFAULT),
			subjectKeyPair.getPublic(),
			new X500Name(RFC4519Style.INSTANCE, subjectName),
			issuerPrivateKey,
			new X500Name(RFC4519Style.INSTANCE, issuerName),
			issuerSignatureAlgorithm,
			issuerSignatureProvider,
			subjectExtensions
		);
		final List<Certificate> list = new ArrayList<>();
		list.add(subjectCertificate);
		if (issuerKeyStoreManager != null) {
			list.addAll(Arrays.asList(issuerKeyStoreManager.entry.getCertificateChain()));
		}
		final Certificate[] subjectCertificateChain = list.toArray(new Certificate[0]);

		// Print certificate chain
		final List<byte[]> certificateBytes = new ArrayList<>(subjectCertificateChain.length);
		Arrays.stream(subjectCertificateChain).forEach(c -> {
			try { certificateBytes.add(c.getEncoded()); } catch (CertificateEncodingException e) { /* do nothing */ }
		});
		PemUtil.printPem("Cert chain", "CERTIFICATE", certificateBytes.toArray(new byte[0][]));

		// Save entry. If SunPKCS11, ephemeral key pair is converted to permanent PKCS11 objects, and certificate chain is added with it. 
		subjectKeyStore.setKeyEntry(subjectName, subjectKeyPair.getPrivate(), subjectKeyStoreEntryPassword, subjectCertificateChain);
		final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) subjectKeyStore.getEntry(subjectName, new KeyStore.PasswordProtection(subjectKeyStoreEntryPassword));
		return new KeyStoreManager(subjectKeyStore, subjectKeyStoreProvider, subjectKeyStorePassword, entry, subjectName, subjectKeyStoreEntryPassword, subjectSignatureProvider);
	}

	private static class ProviderCallbackHandler implements CallbackHandler {
		final char[] keyStorePassword;
		private ProviderCallbackHandler(final char[] keyStorePassword) {
			this.keyStorePassword = keyStorePassword;
		}
		@Override public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (final Callback callback : callbacks) {
				if (callback instanceof PasswordCallback passwordCallback) {
					passwordCallback.setPassword(this.keyStorePassword);
				}
			}
		}
	}

	private static void printKeyStoreEntryAliases(final KeyStore keyStore, final AuthProvider authProvider) throws Exception {
		final StringBuilder sb = new StringBuilder(authProvider.getName() + " existing entries:\n");
		for (final String alias : Collections.list(keyStore.aliases())) {
			sb.append("Entry[").append(alias).append("]: cert=").append(keyStore.isCertificateEntry(alias)).append(", key=").append(keyStore.isKeyEntry(alias)).append('\n');
			keyStore.deleteEntry(alias);
		}
		LOGGER.info(sb.toString());
	}

	@SuppressWarnings("unused")
	private static byte[] getKeyStoreBytes(final char[] subjectKeyStorePassword, final KeyStore subjectKeyStore) throws Exception {
		final byte[] keyStoreBytes;
		try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			subjectKeyStore.store(baos, subjectKeyStorePassword);
			keyStoreBytes = baos.toByteArray();
		}
		return keyStoreBytes;
	}
}
