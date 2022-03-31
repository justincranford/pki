package com.github.justincranford.pki;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeThat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.AuthProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

@DisplayName("Test Mutual TLS")
class TestMutualTls {
	private static final Logger LOGGER = LoggerFactory.getLogger(TestMutualTls.class);
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	
	// Client and server SunPKCS11 configs are in /pki/src/test/resources/
	private static final String SUNPKCS11_CLIENT_CA_CONF = TestMutualTls.resourceToFilePath("/SunPKCS11-client-ca-entity.conf");
	private static final String SUNPKCS11_SERVER_CA_CONF = TestMutualTls.resourceToFilePath("/SunPKCS11-server-ca-entity.conf");
	private static final String SUNPKCS11_CLIENT_END_ENTITY_CONF = TestMutualTls.resourceToFilePath("/SunPKCS11-client-end-entity.conf");
	private static final String SUNPKCS11_SERVER_END_ENTITY_CONF = TestMutualTls.resourceToFilePath("/SunPKCS11-server-end-entity.conf");

	private static final Extension[] EXTENSIONS_ROOT_CA;
	private static final Extension[] EXTENSIONS_CLIENT;
	private static final Extension[] EXTENSIONS_SERVER;
	static {
		final int    caPathLenConstraint    = 0; // 0 sub-CAs under the CA, only end-entities
		final String clientSanEmail         = "client1@example.com";
		final String clientSanDirectoryName = "CN=client1,OU=org unit,O=orgDC=example,DC=com";
		final String serverSanHostname      = "localhost";
		final String serverSanAddressIp4    = "127.0.0.1";
		final String serverSanAddressIp6    = "::1";
		try {
			EXTENSIONS_ROOT_CA = new Extension[] {
				new Extension(Extension.basicConstraints, true, new BasicConstraints(caPathLenConstraint).toASN1Primitive().getEncoded()),
				new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign).toASN1Primitive().getEncoded())
			};
			EXTENSIONS_CLIENT = new Extension[] {
				new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
				new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).toASN1Primitive().getEncoded()),
				new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.rfc822Name, clientSanEmail)).addName(new GeneralName(GeneralName.directoryName, clientSanDirectoryName)).build().toASN1Primitive().getEncoded())
			};
			EXTENSIONS_SERVER = new Extension[] {
				new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
				new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded()),
				new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.dNSName, serverSanHostname)).addName(new GeneralName(GeneralName.iPAddress, serverSanAddressIp4)).addName(new GeneralName(GeneralName.iPAddress, serverSanAddressIp6)).build().toASN1Primitive().getEncoded())
			};
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	// Root CA, Sub CA, Cross-cert, Client/Server End Entity, Client/Server self-signed, etc
	record Entity(
		Provider signatureProvider, // SunRsaSign, SunEC, SunPKCS11
		char[] password, // PKCS12 file integrity, PKCS11 HSM slot authentication
		Provider keyStoreProvider, // SunJSSE, SunPKCS11
		KeyStore keyStore, // PKCS12, PKCS11
		char[] entryPassword, // PKCS12 non-null, PKCS11 null
		String alias, // PrivateKeyEntry alias
		KeyStore.PrivateKeyEntry entry // PKCS12 in-memory private key, PKCS11 in-HSM private key identifier
	) {}

	private Entity clientCaEntity;
	private Entity serverCaEntity;
	private Entity clientEndEntity;
	private Entity serverEndEntity;
	private HttpsServer httpsServer;

//	@BeforeAll static void beforeAll() {
//		Security.addProvider(new BouncyCastleProvider());	// Required if making any JCA/JCE calls to BC
//	}
//
//	@AfterAll static void afterAll() {
//		Security.removeProvider("BC");	// Cleanup in case other tests want to add/remove BC provider
//	}

	@AfterEach void afterEach() throws Exception {
		if (httpsServer != null) {
			httpsServer.stop(0);
		}
		TestMutualTls.logoutSunPkcs11(this.clientCaEntity);
		TestMutualTls.logoutSunPkcs11(this.serverCaEntity);
		TestMutualTls.logoutSunPkcs11(this.clientEndEntity);
		TestMutualTls.logoutSunPkcs11(this.serverEndEntity);
	}

	@Test void testMutualTlsAllPkcs12() throws Exception {
		this.clientCaEntity  = TestMutualTls.createEntity(null,                "DC=Client CA", "RSA", "ClientCA".toCharArray(), "ClientCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		this.serverCaEntity  = TestMutualTls.createEntity(null,                "DC=Server CA", "EC",  "ServerCA".toCharArray(), "ServerCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		this.clientEndEntity = TestMutualTls.createEntity(this.clientCaEntity, "CN=Client",    "EC",  "Client".toCharArray(),   "Client".toCharArray(),   EXTENSIONS_CLIENT, null);
		this.serverEndEntity = TestMutualTls.createEntity(this.serverCaEntity, "CN=Server",    "RSA", "Server".toCharArray(),   "Server".toCharArray(),   EXTENSIONS_SERVER, null);
		this.mutualTlsHelper();
	}
	@Test void testMutualTlsAllPkcs11() throws Exception {
		this.checkForSoftHsm2ConfEnvVariable();
		this.clientCaEntity  = TestMutualTls.createEntity(null,                "DC=Client CA", "RSA", "hsmslotpwd".toCharArray(), null, EXTENSIONS_ROOT_CA, SUNPKCS11_CLIENT_CA_CONF);
		this.serverCaEntity  = TestMutualTls.createEntity(null,                "DC=Server CA", "EC",  "hsmslotpwd".toCharArray(), null, EXTENSIONS_ROOT_CA, SUNPKCS11_SERVER_CA_CONF);
		this.clientEndEntity = TestMutualTls.createEntity(this.clientCaEntity, "CN=Client",    "EC",  "hsmslotpwd".toCharArray(), null, EXTENSIONS_CLIENT,  SUNPKCS11_CLIENT_END_ENTITY_CONF);
		this.serverEndEntity = TestMutualTls.createEntity(this.serverCaEntity, "CN=Server",    "RSA", "hsmslotpwd".toCharArray(), null, EXTENSIONS_SERVER,  SUNPKCS11_SERVER_END_ENTITY_CONF);
		this.mutualTlsHelper();
	}
	@Test void testMutualTlsMixedPkcs12AndPkcs11() throws Exception {
		if (SECURE_RANDOM.nextBoolean()) {
			this.clientCaEntity  = TestMutualTls.createEntity(null,                "DC=Client CA", "RSA", "ClientCA".toCharArray(),   "ClientCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.clientCaEntity  = TestMutualTls.createEntity(null,                "DC=Client CA", "RSA", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_ROOT_CA, SUNPKCS11_CLIENT_CA_CONF);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			this.serverCaEntity  = TestMutualTls.createEntity(null,                "DC=Server CA", "EC",  "ServerCA".toCharArray(),   "ServerCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.serverCaEntity  = TestMutualTls.createEntity(null,                "DC=Server CA", "EC",  "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_ROOT_CA, SUNPKCS11_SERVER_CA_CONF);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			this.clientEndEntity = TestMutualTls.createEntity(this.clientCaEntity, "CN=Client",    "EC",  "Client".toCharArray(),     "Client".toCharArray(),   EXTENSIONS_CLIENT,  null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.clientEndEntity = TestMutualTls.createEntity(this.clientCaEntity, "CN=Client",    "EC",  "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_CLIENT,  SUNPKCS11_CLIENT_END_ENTITY_CONF);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			this.serverEndEntity = TestMutualTls.createEntity(this.serverCaEntity, "CN=Server",    "RSA", "Server".toCharArray(),     "Server".toCharArray(),   EXTENSIONS_SERVER,  null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.serverEndEntity = TestMutualTls.createEntity(this.serverCaEntity, "CN=Server",    "RSA", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_SERVER,  SUNPKCS11_SERVER_END_ENTITY_CONF);
		}
		this.mutualTlsHelper();
	}

	/**
	 * Create root CA, sub CA, RA, cross-cert, CA-signed end-entity, self-signed end-entity, etc
	 * @param issuerEntity Null if self-signed, otherwise it is a non-null issuer 
	 * @param subjectRelativeName Subject RDN, where Subject DN will be SubjectRDN,IssuerDN or SubjectRDN (self-issued)
	 * @param subjectKeyPairAlgorithm RSA or EC 
	 * @param subjectKeyStorePassword PKCS#12 or PKCS11 keystore password
	 * @param subjectKeyStoreEntryPassword PKCS#12 entry password, or null for PKCS11 entries
	 * @param subjectExtensions Array of extensions to add to the subject certificate
	 * @param subjectSunpkcs11Conf Null for PKCS#12, non-null file path for PKCS#11
	 * @return Entity object containing links to the KeyStore, KeysStore provider, password, alias, entry password, and signature provider
	 * @throws Exception Unexpected error
	 */
	private static Entity createEntity(
		final Entity issuerEntity,					// null for Root CA self-signed
		final String subjectRelativeName,			// "CN=Client End Entity,serial=123";
		final String subjectKeyPairAlgorithm,		// "EC";
		final char[] subjectKeyStorePassword,		// "Client".toCharArray();
		final char[] subjectKeyStoreEntryPassword,	// "Client".toCharArray();
		final Extension[] subjectExtensions,		// BasicConstraints, KeyUsage, ExtendedKeyUsage, GeneralNames, etc
		final String subjectSunpkcs11Conf			// SUNPKCS11_CLIENT_END_ENTITY_CONF resolved file path
	) throws Exception {
		final Provider subjectKeyPairGeneratorProvider;	// SunPKCS11, SunRsaSign/SunEC
		final KeyPair  subjectKeyPair;					// RSA or EC; generated and stored in-memory or in-hardware 
		final Provider subjectKeyStoreProvider;			// SunPKCS11, SunPKCS11
		final KeyStore subjectKeyStore;					// PKCS11, PKCS12
		final Provider subjectSignatureProvider;
		if (subjectSunpkcs11Conf == null) {
			subjectSignatureProvider = subjectKeyPairGeneratorProvider = subjectKeyPairAlgorithm.equals("RSA") ? Security.getProvider("SunRsaSign") : Security.getProvider("SunEC");
			subjectKeyPair = TestMutualTls.generateKeyPair(subjectKeyPairAlgorithm, subjectKeyPairGeneratorProvider);
			subjectKeyStoreProvider = Security.getProvider("SunJSSE");
			subjectKeyStore = KeyStore.getInstance("PKCS12", subjectKeyStoreProvider);
			subjectKeyStore.load(null, null);
		} else {
			final AuthProvider authProvider = (AuthProvider) Security.getProvider("SunPKCS11").configure(subjectSunpkcs11Conf); // SunPKCS11 RSA||EC
			final CallbackHandler loginCallbackHandler = new ProviderCallbackHandler(subjectKeyStorePassword); // PKCS11 C_Login pwd for Provider=SunPKCS11 and KeyStore=PKCS11
			authProvider.login(null, loginCallbackHandler);
			Security.addProvider(authProvider); // register AuthProvider so JCA/JCE API calls can use it for crypto operations like KeyPairGenerator
			subjectSignatureProvider = subjectKeyPairGeneratorProvider = authProvider;
			subjectKeyPair = TestMutualTls.generateKeyPair(subjectKeyPairAlgorithm, authProvider);
			subjectKeyStoreProvider = authProvider;
			subjectKeyStore = KeyStore.Builder.newInstance("PKCS11", authProvider, new KeyStore.CallbackHandlerProtection(loginCallbackHandler)).getKeyStore(); // Keyproxy for network auto-reconnects
			TestMutualTls.printKeyStoreEntryAliases(subjectKeyStore, authProvider);
		}

		final Provider issuerSignatureProvider;
		final String issuerSignatureAlgorithm;
		final PrivateKey issuerPrivateKey;
		final String issuerName;
		final String subjectName;
		if (issuerEntity == null) {
			issuerSignatureProvider = subjectSignatureProvider;
			issuerSignatureAlgorithm = subjectKeyPairAlgorithm.equals("RSA") ? "SHA512withRSA" : "SHA512withECDSA";
			issuerPrivateKey = subjectKeyPair.getPrivate();
			subjectName = issuerName = subjectRelativeName;
		} else {
			issuerSignatureProvider = issuerEntity.signatureProvider;
			issuerSignatureAlgorithm = issuerEntity.entry.getPrivateKey().getAlgorithm().equals("RSA") ? "SHA512withRSA" : "SHA512withECDSA";
			issuerPrivateKey = issuerEntity.entry.getPrivateKey();
			issuerName = ((X509Certificate)issuerEntity.entry.getCertificate()).getSubjectX500Principal().getName(X500Principal.RFC2253);
			subjectName = subjectRelativeName + "," + issuerName;
		}

		final Certificate subjectCertificate = TestMutualTls.createCert(
			Date.from(ZonedDateTime.of(1970, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()),
			Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
			new BigInteger(159, SECURE_RANDOM),
			subjectKeyPair.getPublic(),
			new X500Name(subjectName),
			issuerPrivateKey,
			new X500Name(issuerName),
			issuerSignatureAlgorithm,
			issuerSignatureProvider,
			subjectExtensions
		);
		final List<Certificate> list = new ArrayList<>();
		list.add(subjectCertificate);
		if (issuerEntity != null) {
			Arrays.stream(issuerEntity.entry.getCertificateChain()).forEach(c -> list.add(c));
		}
		final Certificate[] subjectCertificateChain = list.toArray(new X509Certificate[list.size()]);

		// Print certificate chain
		final List<byte[]> certificateBytes = new ArrayList<>(subjectCertificateChain.length);
		Arrays.stream(subjectCertificateChain).forEach(c -> {
			try { certificateBytes.add(c.getEncoded()); } catch (CertificateEncodingException e) { /* do nothing */ }
		});
		printPem("Cert chain", "CERTIFICATE", certificateBytes.toArray(new byte[0][]));

		// Save entry. If SunPKCS11, ephemeral key pair is converted to permanent PKCS11 objects, and certificate chain is added with it. 
		subjectKeyStore.setKeyEntry(subjectName, subjectKeyPair.getPrivate(), subjectKeyStoreEntryPassword, subjectCertificateChain);
		return new Entity(subjectSignatureProvider, subjectKeyStorePassword, subjectKeyStoreProvider, subjectKeyStore, subjectKeyStoreEntryPassword, subjectName, (KeyStore.PrivateKeyEntry) subjectKeyStore.getEntry(subjectName, new KeyStore.PasswordProtection(subjectKeyStoreEntryPassword)));
	}

	private void mutualTlsHelper() throws Exception {
		final String expectedResponse = "Hello World " + SECURE_RANDOM.nextInt() + "\n";
		final byte[] expectedResponseBytes = expectedResponse.getBytes();

		{	// CMS Example
			// Outer encryptions (KTRI=>RSA)
			final JceKeyTransRecipientInfoGenerator ktriGenerator1 = new JceKeyTransRecipientInfoGenerator((X509Certificate) this.serverEndEntity.entry.getCertificate()).setProvider("SunJCE");
			// Inner encryption (AES-256-CBC)
			final OutputEncryptor cmsContentEncryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("SunJCE").build();
			// Generate
			final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
			cmsEnvelopedDataGenerator.addRecipientInfoGenerator(ktriGenerator1); // outer encryption(s)
			final CMSTypedData cmsContent = new CMSProcessableByteArray(expectedResponseBytes);
			final CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(cmsContent, cmsContentEncryptor); // inner encryption
			final byte[] cmsEnvelopedDataBytes = cmsEnvelopedData.getEncoded();
			// Print
			printPem("Payload", "CMS", cmsEnvelopedDataBytes);

			// RSA outer encryptions
			final RecipientId recipientId = new JceKeyTransRecipientId((X509Certificate) this.serverEndEntity.entry.getCertificate());
			final RecipientInformationStore recipientInformationStore = cmsEnvelopedData.getRecipientInfos();
			final RecipientInformation recipientInformation = recipientInformationStore.get(recipientId);
			assertNotNull(recipientInformation);
			final JceKeyTransRecipient ktriRecipient = new JceKeyTransEnvelopedRecipient(this.serverEndEntity.entry.getPrivateKey()).setProvider((this.serverEndEntity.keyStoreProvider instanceof AuthProvider authProvider) ? serverEndEntity.keyStoreProvider : Security.getProvider("SunJCE"));
			final byte[] decryptedData = recipientInformation.getContent(ktriRecipient);
			assertThat(decryptedData, is(equalTo(expectedResponseBytes)));
		}

		// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
		final SSLContext serverSslContext = createServerSslContext(this.serverEndEntity, (X509Certificate) this.clientEndEntity.entry.getCertificateChain()[1]);
		this.httpsServer = HttpsServer.create(new InetSocketAddress("localhost", 443), 0);
		this.httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverSslContext) {
			@Override public void configure(final HttpsParameters httpsParameters) {
				final SSLEngine engine = serverSslContext.createSSLEngine();
				httpsParameters.setNeedClientAuth(true);
				httpsParameters.setCipherSuites(engine.getEnabledCipherSuites());
				httpsParameters.setProtocols(engine.getEnabledProtocols());
				httpsParameters.setSSLParameters(serverSslContext.getSupportedSSLParameters());
			}
		});
		this.httpsServer.createContext("/test", new HttpHandler() {
			@Override public void handle(final HttpExchange httpExchange) throws IOException {
				try (final OutputStream os = httpExchange.getResponseBody()) {
					httpExchange.sendResponseHeaders(200, expectedResponse.length());
					os.write(expectedResponse.getBytes(StandardCharsets.UTF_8));
				}
			}
		});
		this.httpsServer.setExecutor(null); // creates a default executor
		this.httpsServer.start();

		// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
		final SSLContext clientSslContext = createClientSslContext(this.clientEndEntity, (X509Certificate) this.serverEndEntity.entry.getCertificateChain()[1]);
		final HttpClient httpClient = HttpClient.newBuilder().sslContext(clientSslContext).connectTimeout(Duration.ofSeconds(2)).build();

		// Use HTTPS client to send a GET request to the HTTPS server, to verify if TLS handshake succeeds
		final HttpRequest request = HttpRequest.newBuilder().uri(new URI("https://localhost:443/test")).GET().timeout(Duration.ofSeconds(4)).build();
		final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		final HttpHeaders responseHeaders = response.headers();
		LOGGER.info("Server response headers: " + responseHeaders);
		LOGGER.info("Server response body: " + response.body());
		assertThat(response.body(), equalTo(expectedResponse));
	}

	// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
	private SSLContext createClientSslContext(
		final Entity client,
		final X509Certificate serverCaCert
	) throws Exception {
		final KeyStore clientTrustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
		clientTrustStore.load(null, null);
		clientTrustStore.setCertificateEntry("servercacert", serverCaCert); // trust the server CA cert

		final KeyManagerFactory clientKeyManagerFactory = KeyManagerFactory.getInstance("PKIX", "SunJSSE");
		clientKeyManagerFactory.init(client.keyStore, client.entryPassword);
		final KeyManager[] clientKeyManagers = clientKeyManagerFactory.getKeyManagers();

		final TrustManagerFactory clientTrustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		clientTrustManagerFactory.init(clientTrustStore);
		final TrustManager[] clientTrustManagers = clientTrustManagerFactory.getTrustManagers();

		final SSLContext clientSslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
		clientSslContext.init(clientKeyManagers, clientTrustManagers, SECURE_RANDOM);
		return clientSslContext;
	}

	private SSLContext createServerSslContext(
		final Entity server,
		final X509Certificate clientCaCert
	) throws Exception {
		final KeyStore serverTrustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
		serverTrustStore.load(null, null);
		serverTrustStore.setCertificateEntry("clientcacert", clientCaCert);

		final KeyManagerFactory serverKeyManagerFactory = KeyManagerFactory.getInstance("PKIX", "SunJSSE");
		serverKeyManagerFactory.init(server.keyStore, server.entryPassword);
		final KeyManager[] serverKeyManagers = serverKeyManagerFactory.getKeyManagers();

		final TrustManagerFactory serverTrustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		serverTrustManagerFactory.init(serverTrustStore);
		final TrustManager[] serverTrustManagers = serverTrustManagerFactory.getTrustManagers();

		final SSLContext serverSslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
		serverSslContext.init(serverKeyManagers, serverTrustManagers, SECURE_RANDOM);
		return serverSslContext;
	}

	private static X509Certificate createCert(
		final Date notBefore,
		final Date notAfter,
		final BigInteger serialNumber,
		final PublicKey subjectPublicKey,
		final X500Name subjectDN,
		final PrivateKey issuerPrivateKey,
		final X500Name issuerDN,
		final String issuerSigningAlgorithm,
		final Provider issuerSigningProvider,
		final Extension... extensions
	) throws Exception {
		final JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN, subjectPublicKey);
		for (final Extension extension : extensions) {
			if (extension != null) {
				jcaX509v3CertificateBuilder.addExtension(extension);
			}
		}
		final JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(issuerSigningAlgorithm);
		if (issuerSigningProvider != null) {
			jcaContentSignerBuilder.setProvider(issuerSigningProvider);
		}
		final ContentSigner contentSigner = jcaContentSignerBuilder.build(issuerPrivateKey);
		X509CertificateHolder x509CertificateHolder = jcaX509v3CertificateBuilder.build(contentSigner);
		final JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
		return jcaX509CertificateConverter.getCertificate(x509CertificateHolder);
		
	}

	private static void printPem(final String msg, final String pemType, final byte[]... payloads) throws Exception {
		LOGGER.info(msg);
		for (final byte[] payload : payloads) {
			System.out.println("-----BEGIN "+pemType+"-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(payload) + "\n-----END "+pemType+"-----");
		}
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

	private static String resourceToFilePath(final String resource) throws IllegalArgumentException {
		try {
			return new File(TestMutualTls.class.getResource(resource).toURI()).getAbsolutePath();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("");
		}
	}

	private static void logoutSunPkcs11(final Entity entity) {
		if ((entity != null) && (entity.keyStoreProvider instanceof AuthProvider authProvider)) {
			try {
				LOGGER.info("Logout " + entity.keyStoreProvider.getName());
				authProvider.logout();
			} catch (SecurityException|LoginException e) {
				LOGGER.error("Logout " + entity.keyStoreProvider.getName() + " exception", e);
			}
			try {
				LOGGER.info("Remove " + entity.keyStoreProvider.getName());
				Security.removeProvider(authProvider.getName());
			} catch (SecurityException e) {
				LOGGER.error("Remove " + entity.keyStoreProvider.getName() + " exception", e);
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

	private static byte[] getKeyStoreBytes(final char[] subjectKeyStorePassword, final KeyStore subjectKeyStore) throws Exception {
		final byte[] keyStoreBytes;
		try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			subjectKeyStore.store(baos, subjectKeyStorePassword);
			keyStoreBytes = baos.toByteArray();
		}
		return keyStoreBytes;
	}

	private static KeyPair generateKeyPair(final String algorithm, final Provider provider) throws Exception {
		final KeyPairGenerator subjectKeyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
		if (algorithm.equals("RSA")) {
			subjectKeyPairGenerator.initialize(2048); // NIST RSA-3072
		} else {
			subjectKeyPairGenerator.initialize(new ECGenParameterSpec("secp521r1")); // NIST EC P-521
		}
		return subjectKeyPairGenerator.generateKeyPair();
	}

	private void checkForSoftHsm2ConfEnvVariable() {
		assumeThat("Environment variable SOFTHSM2_CONF required for SunPKCS11 test", System.getenv("SOFTHSM2_CONF"), is(not(nullValue())));
	}
}
