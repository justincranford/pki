package com.github.justincranford.pki;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

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
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
	private static final String SUNPKCS11_CLIENT_CONF = resourceToFilePath("/SunPKCS11-client.conf");
	private static final String SUNPKCS11_SERVER_CONF = resourceToFilePath("/SunPKCS11-server.conf");

	private static String resourceToFilePath(final String resource) throws IllegalArgumentException {
		try {
			return new File(TestMutualTls.class.getResource(resource).toURI()).getAbsolutePath();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("");
		}
	}

	record EndEntity(
		Provider provider, // SunJSSE, SunPKCS11
		char[] password, // PKCS12 file integrity, PKCS11 HSM slot authentication
		KeyStore keyStore, // PKCS12, PKCS11
		byte[] keyStoreBytes, // PKCS12 keystore file contents, PKCS11 config file contents
		String alias,
		char[] entryPassword, // PKCS12 non-null, PKCS11 null
		KeyStore.PrivateKeyEntry entry // PKCS12 in-memory private key, PKCS11 in-HSM private key identifier
	) {}

	private EndEntity client;
	private EndEntity server;
	private HttpsServer httpsServer;

	@BeforeAll
	static void beforeAll() throws Exception {
		LOGGER.info("Before all test methods");
	}

	@BeforeEach
	void beforeEach() {
		LOGGER.info("Before each test method");
	}

	@AfterEach
	void afterEach() throws Exception {
		if (httpsServer != null) {
			httpsServer.stop(0);
		}
		if ((client != null) && (client.provider instanceof AuthProvider authProvider)) {
			LOGGER.info("Logout client");
			authProvider.logout();
		}
		if ((server != null) && (server.provider instanceof AuthProvider authProvider)) {
			LOGGER.info("Logout server");
			authProvider.logout();
		}
		LOGGER.info("After each test method");
	}

	@AfterAll
	static void afterAll() {
		LOGGER.info("After all test methods");
	}

	@Test
	void testMutualTls() throws Exception {
		// private key and cert chain
		client = createClient();
		server = createServer();

		final String expectedResponse = "Hello World " + SECURE_RANDOM.nextInt() + "\n";

		// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
		final SSLContext serverSslContext = createServerSslContext(server, (X509Certificate) client.entry.getCertificateChain()[1]);
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
		final SSLContext clientSslContext = createClientSslContext(client, (X509Certificate) server.entry.getCertificateChain()[1]);
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
		final EndEntity client,
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
		final EndEntity server,
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

	private static EndEntity createClient() throws Exception {
		final char[] keyStorePassword = "clientuser".toCharArray();
		final Provider keyStoreProvider;
		final KeyStore keyStore;
		final Provider keyPairGeneratorProvider;
		final Provider signatureProvider;
		if (System.getenv("SOFTHSM2_CONF") == null) {
			keyStoreProvider = Security.getProvider("SunJSSE");
			keyStore = KeyStore.getInstance("PKCS12", keyStoreProvider);
			keyStore.load(null, null);
			keyPairGeneratorProvider = signatureProvider = Security.getProvider("SunEC");
		} else {
			final ProviderCallbackHandler providerCallbackHandler = new ProviderCallbackHandler(keyStorePassword);
			final AuthProvider authProvider = (AuthProvider) Security.getProvider("SunPKCS11").configure(SUNPKCS11_CLIENT_CONF);
			authProvider.login(null, providerCallbackHandler);
			keyStoreProvider = authProvider;
			Security.addProvider(authProvider); // register provider
			final KeyStore.CallbackHandlerProtection keyStoreCallbackHandler = new KeyStore.CallbackHandlerProtection(providerCallbackHandler);
			final KeyStore.Builder keyStoreBuilder = KeyStore.Builder.newInstance("PKCS11", authProvider, keyStoreCallbackHandler);
			keyStore = keyStoreBuilder.getKeyStore();
			keyPairGeneratorProvider = signatureProvider = keyStoreProvider;
			final StringBuilder sb = new StringBuilder(authProvider.getName() + " existing entries:\n");
			for (final String alias : Collections.list(keyStore.aliases())) {
				sb.append("Entry[").append(alias).append("]: cert=").append(keyStore.isCertificateEntry(alias)).append(", key=").append(keyStore.isKeyEntry(alias)).append('\n');
				keyStore.deleteEntry(alias);
			}
			LOGGER.info(sb.toString());
		}

		final KeyPairGenerator clientKeyPairGenerator = KeyPairGenerator.getInstance("EC", keyPairGeneratorProvider);
		clientKeyPairGenerator.initialize(new ECGenParameterSpec("secp521r1")); // NIST P-521 

		final KeyPair clientCaKeyPair = clientKeyPairGenerator.generateKeyPair();
		final KeyStore.PrivateKeyEntry clientCa = new KeyStore.PrivateKeyEntry(
			clientCaKeyPair.getPrivate(),
			new X509Certificate[] {
				createCert(
					Date.from(ZonedDateTime.of(1970, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()),
					Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
					new BigInteger(159, SECURE_RANDOM),
					clientCaKeyPair.getPublic(),
					new X500Name("DC=Client Root CA"),
					clientCaKeyPair.getPrivate(),
					new X500Name("DC=Client Root CA"),
					"SHA512withECDSA",
					signatureProvider,
					new Extension(Extension.basicConstraints, true, new BasicConstraints(0).toASN1Primitive().getEncoded()),
					new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign).toASN1Primitive().getEncoded())
				)
			}
		);
		final KeyPair clientKeyPair = clientKeyPairGenerator.generateKeyPair();
		final KeyStore.PrivateKeyEntry clientEndEntity = new KeyStore.PrivateKeyEntry(
			clientKeyPair.getPrivate(),
			new X509Certificate[] {
				createCert(
					Date.from(ZonedDateTime.of(1970, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()),
					Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
					new BigInteger(159, SECURE_RANDOM),
					clientKeyPair.getPublic(),
					new X500Name("CN=Client End Entity, DC=Client Root CA"),
					clientCaKeyPair.getPrivate(),
					new X500Name("DC=Client Root CA"),
					"SHA512withECDSA",
					signatureProvider,
					new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
					new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).toASN1Primitive().getEncoded()),
					new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.rfc822Name, "client@example.com")).build().toASN1Primitive().getEncoded())
				),
				(X509Certificate) clientCa.getCertificateChain()[0]
			}
		);
		printCertChain("Client cert chain", (X509Certificate[]) clientEndEntity.getCertificateChain());

		final String alias = "clientEndEntityAlias";
		final KeyStore.PasswordProtection entryPassword = new KeyStore.PasswordProtection("clientEndEntityPassword".toCharArray());
		keyStore.setEntry(alias, clientEndEntity, entryPassword);
		final byte[] keyStoreBytes;
		if (System.getenv("SOFTHSM2_CONF") == null) {
			try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				keyStore.store(baos, keyStorePassword);
				keyStoreBytes = baos.toByteArray();
			}
		} else {
			keyStoreBytes = null;
		}
		return new EndEntity(keyStoreProvider, keyStorePassword, keyStore, keyStoreBytes, alias, entryPassword.getPassword(), (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, entryPassword));
	}

	private static EndEntity createServer() throws Exception {
		final char[] keyStorePassword = "serveruser".toCharArray();
		final Provider keyStoreProvider;
		final KeyStore keyStore;
		final Provider keyPairGeneratorProvider;
		final Provider signatureProvider;
		if (System.getenv("SOFTHSM2_CONF") == null) {
			keyStoreProvider = Security.getProvider("SunJSSE");
			keyStore = KeyStore.getInstance("PKCS12", keyStoreProvider);
			keyStore.load(null, null);
			keyPairGeneratorProvider = signatureProvider = Security.getProvider("SunEC");
		} else {
			final ProviderCallbackHandler providerCallbackHandler = new ProviderCallbackHandler(keyStorePassword);
			final AuthProvider authProvider = (AuthProvider) Security.getProvider("SunPKCS11").configure(SUNPKCS11_SERVER_CONF);
			authProvider.login(null, providerCallbackHandler);
			keyStoreProvider = authProvider;
			Security.addProvider(authProvider); // register provider
			final KeyStore.CallbackHandlerProtection keyStoreCallbackHandler = new KeyStore.CallbackHandlerProtection(providerCallbackHandler);
			final KeyStore.Builder keyStoreBuilder = KeyStore.Builder.newInstance("PKCS11", authProvider, keyStoreCallbackHandler);
			keyStore = keyStoreBuilder.getKeyStore();
			keyPairGeneratorProvider = signatureProvider = keyStoreProvider;
			final StringBuilder sb = new StringBuilder(authProvider.getName() + " existing entries:\n");
			for (final String alias : Collections.list(keyStore.aliases())) {
				sb.append("Entry[").append(alias).append("]: cert=").append(keyStore.isCertificateEntry(alias)).append(", key=").append(keyStore.isKeyEntry(alias)).append('\n');
				keyStore.deleteEntry(alias);
			}
			LOGGER.info(sb.toString());
		}

		final KeyPairGenerator serverKeyPairGenerator = KeyPairGenerator.getInstance("EC", keyPairGeneratorProvider);
		serverKeyPairGenerator.initialize(new ECGenParameterSpec("secp521r1")); // NIST P-521 

		final KeyPair serverCaKeyPair = serverKeyPairGenerator.generateKeyPair();
		final KeyStore.PrivateKeyEntry serverCa = new KeyStore.PrivateKeyEntry(
			serverCaKeyPair.getPrivate(),
			new X509Certificate[] {
				createCert(
					Date.from(ZonedDateTime.of(1970, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()),
					Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
					new BigInteger(159, SECURE_RANDOM),
					serverCaKeyPair.getPublic(),
					new X500Name("DC=Client Root CA"),
					serverCaKeyPair.getPrivate(),
					new X500Name("DC=Client Root CA"),
					"SHA512withECDSA",
					signatureProvider,
					new Extension(Extension.basicConstraints, true, new BasicConstraints(0).toASN1Primitive().getEncoded()),
					new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign).toASN1Primitive().getEncoded())
				)
			}
		);
		final KeyPair serverKeyPair = serverKeyPairGenerator.generateKeyPair();
		final KeyStore.PrivateKeyEntry serverEndEntity = new KeyStore.PrivateKeyEntry(
			serverKeyPair.getPrivate(),
			new X509Certificate[] {
				createCert(
					Date.from(ZonedDateTime.of(1970, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()),
					Date.from(ZonedDateTime.of(2099, 12, 31, 23, 59, 59, 999999999, ZoneOffset.UTC).toInstant()),
					new BigInteger(159, SECURE_RANDOM),
					serverKeyPair.getPublic(),
					new X500Name("CN=Client End Entity, DC=Client Root CA"),
					serverCaKeyPair.getPrivate(),
					new X500Name("DC=Client Root CA"),
					"SHA512withECDSA",
					signatureProvider,
					new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
					new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive().getEncoded()),
					new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.dNSName, "localhost")).build().toASN1Primitive().getEncoded())
				),
				(X509Certificate) serverCa.getCertificateChain()[0]
			}
		);
		printCertChain("Client cert chain", (X509Certificate[]) serverEndEntity.getCertificateChain());

		final String alias = "serverEndEntityAlias";
		final KeyStore.PasswordProtection entryPassword = new KeyStore.PasswordProtection("serverEndEntityPassword".toCharArray());
		keyStore.setEntry(alias, serverEndEntity, entryPassword);
		final byte[] keyStoreBytes;
		if (System.getenv("SOFTHSM2_CONF") == null) {
			try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				keyStore.store(baos, keyStorePassword);
				keyStoreBytes = baos.toByteArray();
			}
		} else {
			keyStoreBytes = null;
		}
		return new EndEntity(keyStoreProvider, keyStorePassword, keyStore, keyStoreBytes, alias, entryPassword.getPassword(), (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, entryPassword));
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

	private static void printCertChain(final String msg, final X509Certificate... certs) throws Exception {
		LOGGER.info(msg);
		for (final X509Certificate cert : certs) {
			System.out.println("-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()) + "\n-----END CERTIFICATE-----");
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
}
