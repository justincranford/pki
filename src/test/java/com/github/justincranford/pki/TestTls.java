package com.github.justincranford.pki;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assume.assumeNotNull;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.login.LoginException;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.justincranford.common.CmsUtil;
import com.github.justincranford.common.SecureRandomUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

@DisplayName("Test Mutual TLS")
class TestTls {
	private static final Logger LOGGER = LoggerFactory.getLogger(TestTls.class);

	private KeyStoreManager clientCa;	// client self-signed root CA, or null if client is self-signed 
	private KeyStoreManager serverCa;	// server self-signed root CA, or null if server is self-signed
	private KeyStoreManager client;		// client can be client CA-signed or self-signed
	private KeyStoreManager server;		// server can be server CA-signed or self-signed

	// Client and server SunPKCS11 configs are in /pki/src/test/resources/
	private static final String SUNPKCS11_CLIENT_CA_CONF = TestTls.resourceToFilePath("/SunPKCS11-client-ca-entity.conf");
	private static final String SUNPKCS11_SERVER_CA_CONF = TestTls.resourceToFilePath("/SunPKCS11-server-ca-entity.conf");
	private static final String SUNPKCS11_CLIENT_END_ENTITY_CONF = TestTls.resourceToFilePath("/SunPKCS11-client-end-entity.conf");
	private static final String SUNPKCS11_SERVER_END_ENTITY_CONF = TestTls.resourceToFilePath("/SunPKCS11-server-end-entity.conf");

	private static final Extension[] EXTENSIONS_ROOT_CA;
	private static final Extension[] EXTENSIONS_CLIENT;
	private static final Extension[] EXTENSIONS_SERVER;
	static {
		final int    caPathLenConstraint    = 0; // No sub-CAs allowed under root CA, only end-entities allowed under root CA
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

	@BeforeAll static void beforeAll() {
		Security.addProvider(new BouncyCastleProvider());	// Register BC provider, required if making direct or indirect JCA/JCE calls to BC
	}

	@AfterAll static void afterAll() {
		Security.removeProvider("BC");	// Remove BC provider, so other test classes can add and remove BC provider
	}

	@AfterEach void afterEach() throws Exception {
		TestTls.logoutSunPkcs11(this.clientCa);
		TestTls.logoutSunPkcs11(this.serverCa);
		TestTls.logoutSunPkcs11(this.client);
		TestTls.logoutSunPkcs11(this.server);
	}

	@Test void testMutualTlsSelfSignedAllP12() throws Exception {
		this.clientCa = null; // no client CA => client will be self-issued and self-signed
		this.serverCa = null; // no server CA => server will be self-issued and self-signed
		this.client   = KeyStoreManager.create(null,          "CN=Client",    "EC",  "Client".toCharArray(),     "Client".toCharArray(),   EXTENSIONS_CLIENT, null);
		this.server   = KeyStoreManager.create(null,          "CN=Server",    "RSA", "Server".toCharArray(),     "Server".toCharArray(),   EXTENSIONS_SERVER, null);
		this.mutualTlsHelper();
	}
	@Test void testMutualTlsSelfSignedAllP11() throws Exception {
		this.checkForSoftHsm2ConfEnvVariable();
		this.clientCa = null; // no client CA => client will be self-issued and self-signed
		this.serverCa = null; // no server CA => server will be self-issued and self-signed
		this.client   = KeyStoreManager.create(null,          "CN=Client",    "EC",  "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_CLIENT,  SUNPKCS11_CLIENT_END_ENTITY_CONF);
		this.server   = KeyStoreManager.create(null,          "CN=Server",    "RSA", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_SERVER,  SUNPKCS11_SERVER_END_ENTITY_CONF);
		this.mutualTlsHelper();
	}
	@Test void testMutualTlsCaSignedAllP12() throws Exception {
		this.clientCa = KeyStoreManager.create(null,          "DC=Client CA", "RSA", "ClientCA".toCharArray(),   "ClientCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		this.serverCa = KeyStoreManager.create(null,          "DC=Server CA", "EC",  "ServerCA".toCharArray(),   "ServerCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		this.client   = KeyStoreManager.create(this.clientCa, "CN=Client",    "EC",  "Client".toCharArray(),     "Client".toCharArray(),   EXTENSIONS_CLIENT,  null);
		this.server   = KeyStoreManager.create(this.serverCa, "CN=Server",    "RSA", "Server".toCharArray(),     "Server".toCharArray(),   EXTENSIONS_SERVER,  null);
		this.mutualTlsHelper();
	}
	@Test void testMutualTlsCaSignedAllP11() throws Exception {
		this.checkForSoftHsm2ConfEnvVariable();
		this.clientCa = KeyStoreManager.create(null,          "DC=Client CA", "RSA", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_ROOT_CA, SUNPKCS11_CLIENT_CA_CONF);
		this.serverCa = KeyStoreManager.create(null,          "DC=Server CA", "EC",  "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_ROOT_CA, SUNPKCS11_SERVER_CA_CONF);
		this.client   = KeyStoreManager.create(this.clientCa, "CN=Client",    "EC",  "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_CLIENT,  SUNPKCS11_CLIENT_END_ENTITY_CONF);
		this.server   = KeyStoreManager.create(this.serverCa, "CN=Server",    "RSA", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_SERVER,  SUNPKCS11_SERVER_END_ENTITY_CONF);
		this.mutualTlsHelper();
	}
	@Test void testMutualTlsCaSignedMixedP12AndP11() throws Exception {
		if (SecureRandomUtil.DEFAULT.nextBoolean()) {
			this.clientCa = null;
		} else if (SecureRandomUtil.DEFAULT.nextBoolean()) {
			this.clientCa = KeyStoreManager.create(null,          "DC=Client CA", SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "ClientCA".toCharArray(),   "ClientCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.clientCa = KeyStoreManager.create(null,          "DC=Client CA", SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_ROOT_CA, SUNPKCS11_CLIENT_CA_CONF);
		}
		if (SecureRandomUtil.DEFAULT.nextBoolean()) {
			this.serverCa = null;
		} else if (SecureRandomUtil.DEFAULT.nextBoolean()) {
			this.serverCa = KeyStoreManager.create(null,          "DC=Server CA", SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "ServerCA".toCharArray(),   "ServerCA".toCharArray(), EXTENSIONS_ROOT_CA, null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.serverCa = KeyStoreManager.create(null,          "DC=Server CA", SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_ROOT_CA, SUNPKCS11_SERVER_CA_CONF);
		}
		if (SecureRandomUtil.DEFAULT.nextBoolean()) {
			this.client   = KeyStoreManager.create(this.clientCa, "CN=Client",    SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "Client".toCharArray(),     "Client".toCharArray(),   EXTENSIONS_CLIENT,  null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.client   = KeyStoreManager.create(this.clientCa, "CN=Client",    SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_CLIENT,  SUNPKCS11_CLIENT_END_ENTITY_CONF);
		}
		if (SecureRandomUtil.DEFAULT.nextBoolean()) {
			this.server   = KeyStoreManager.create(this.serverCa, "CN=Server",    SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "Server".toCharArray(),     "Server".toCharArray(),   EXTENSIONS_SERVER,  null);
		} else {
			this.checkForSoftHsm2ConfEnvVariable();
			this.server   = KeyStoreManager.create(this.serverCa, "CN=Server",    SecureRandomUtil.DEFAULT.nextBoolean() ? "RSA" : "EC", "hsmslotpwd".toCharArray(), null,                     EXTENSIONS_SERVER,  SUNPKCS11_SERVER_END_ENTITY_CONF);
		}
		this.mutualTlsHelper();
	}

	private void mutualTlsHelper() throws Exception {
		final String expectedResponse = "Hello World " + SecureRandomUtil.DEFAULT.nextInt() + "\n";

		// SoftHSM2 is missing support for some CMS algorithms 
		if (! (this.client.keyStoreProvider() instanceof AuthProvider authProvider)) {	// CMS Example
			final byte[] expectedResponseBytes = expectedResponse.getBytes();
			final byte[] encryptedDataBytes = CmsUtil.encryptCMSEnvelopedData(
				expectedResponseBytes,
				(X509Certificate) this.server.entry().getCertificate(),	// recpientCertificate
				(X509Certificate) this.client.entry().getCertificate(),	// senderCertificate (ECDH only, not RSA)
				 this.client.entry().getPrivateKey()						// senderPrivateKey  (ECDH only, not RSA)
			);
			final byte[] decryptedDataBytes = CmsUtil.decryptCmsEnvelopedData(
				encryptedDataBytes,
				(X509Certificate) this.server.entry().getCertificate(),
				this.server.entry().getPrivateKey(),
//				(this.server.keyStoreProvider() instanceof AuthProvider authProvider) ? server.keyStoreProvider() : Security.getProvider("SunJCE") // TODO Sun only?
				(this.server.keyStoreProvider() instanceof AuthProvider authProvider) ? server.keyStoreProvider() : Security.getProvider("BC")
			);
			assertThat(decryptedDataBytes, is(equalTo(expectedResponseBytes)));
		}

		// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
		final SSLContext serverSslContext = this.createServerSslContext();
		final HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("localhost", 8443), 0);
		httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverSslContext) {
			@Override public void configure(final HttpsParameters httpsParameters) {
				final SSLEngine engine = serverSslContext.createSSLEngine();
				httpsParameters.setNeedClientAuth(true);
				httpsParameters.setCipherSuites(engine.getEnabledCipherSuites());
				httpsParameters.setProtocols(engine.getEnabledProtocols());
				httpsParameters.setSSLParameters(serverSslContext.getSupportedSSLParameters());
			}
		});
		httpsServer.createContext("/test", new HttpHandler() {
			@Override public void handle(final HttpExchange httpExchange) throws IOException {
				try (final OutputStream os = httpExchange.getResponseBody()) {
					httpExchange.sendResponseHeaders(200, expectedResponse.length());
					os.write(expectedResponse.getBytes(StandardCharsets.UTF_8));
				}
			}
		});
		httpsServer.setExecutor(null); // creates a default executor
		httpsServer.start();
		try {
			// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
			final SSLContext clientSslContext = this.createClientSslContext();
			final HttpClient httpClient = HttpClient.newBuilder().sslContext(clientSslContext).connectTimeout(Duration.ofSeconds(2)).build();

			// Use HTTPS client to send a GET request to the HTTPS server, to verify if TLS handshake succeeds
			final HttpRequest request = HttpRequest.newBuilder().uri(new URI("https://localhost:8443/test")).GET().timeout(Duration.ofSeconds(4)).build();
			final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			final HttpHeaders responseHeaders = response.headers();
			LOGGER.info("Server response headers: " + responseHeaders);
			LOGGER.info("Server response body: " + response.body());
			assertThat(response.body(), equalTo(expectedResponse));
		} finally {
			httpsServer.stop(0);
		}
	}

	// SSLContext = KeyManager(KeyStore) + TrustManager(TrustStore)
	private SSLContext createClientSslContext() throws Exception {
		final Certificate[] serverCertificateChain = this.server.entry().getCertificateChain();
		final X509Certificate lastCertificateServerCertificateChain = (X509Certificate) serverCertificateChain[serverCertificateChain.length-1];
		final KeyStore clientTrustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
		clientTrustStore.load(null, null);
		clientTrustStore.setCertificateEntry("servercacert", lastCertificateServerCertificateChain); // trust the server CA cert

		final KeyManagerFactory clientKeyManagerFactory = KeyManagerFactory.getInstance("PKIX", "SunJSSE");
		clientKeyManagerFactory.init(this.client.keyStore(), this.client.entryPassword());
		final KeyManager[] clientKeyManagers = clientKeyManagerFactory.getKeyManagers();

		final TrustManagerFactory clientTrustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		clientTrustManagerFactory.init(clientTrustStore);
		final TrustManager[] clientTrustManagers = clientTrustManagerFactory.getTrustManagers();

		final SSLContext clientSslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
		clientSslContext.init(clientKeyManagers, clientTrustManagers, SecureRandomUtil.DEFAULT);
		return clientSslContext;
	}

	private SSLContext createServerSslContext() throws Exception {
		final Certificate[] clientCertificateChain = this.client.entry().getCertificateChain();
		final X509Certificate lastCertificateClientCertificateChain = (X509Certificate) clientCertificateChain[clientCertificateChain.length-1];
		final KeyStore serverTrustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
		serverTrustStore.load(null, null);
		serverTrustStore.setCertificateEntry("clientcacert", lastCertificateClientCertificateChain);

		final KeyManagerFactory serverKeyManagerFactory = KeyManagerFactory.getInstance("PKIX", "SunJSSE");
		serverKeyManagerFactory.init(this.server.keyStore(), this.server.entryPassword());
		final KeyManager[] serverKeyManagers = serverKeyManagerFactory.getKeyManagers();

		final TrustManagerFactory serverTrustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		serverTrustManagerFactory.init(serverTrustStore);
		final TrustManager[] serverTrustManagers = serverTrustManagerFactory.getTrustManagers();

		final SSLContext serverSslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
		serverSslContext.init(serverKeyManagers, serverTrustManagers, SecureRandomUtil.DEFAULT);
		return serverSslContext;
	}

	private static String resourceToFilePath(final String resource) throws IllegalArgumentException {
		try {
			return new File(TestTls.class.getResource(resource).toURI()).getAbsolutePath();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("");
		}
	}

	private static void logoutSunPkcs11(final KeyStoreManager entity) {
		if ((entity != null) && (entity.keyStoreProvider() instanceof AuthProvider authProvider)) {
			try {
				LOGGER.info("Logout " + entity.keyStoreProvider().getName());
				authProvider.logout();
			} catch (SecurityException|LoginException e) {
				LOGGER.error("Logout " + entity.keyStoreProvider().getName() + " exception", e);
			}
			try {
				LOGGER.info("Remove " + entity.keyStoreProvider().getName());
				Security.removeProvider(authProvider.getName());
			} catch (SecurityException e) {
				LOGGER.error("Remove " + entity.keyStoreProvider().getName() + " exception", e);
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

	private void checkForSoftHsm2ConfEnvVariable() {
		assumeNotNull("Environment variable SOFTHSM2_CONF required for SunPKCS11 test", System.getenv("SOFTHSM2_CONF"));
	}
}
