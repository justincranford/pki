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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
class TestPkiDomains {
	@SuppressWarnings("unused")
	private static final Logger LOGGER = LoggerFactory.getLogger(TestPkiDomains.class);

	@BeforeAll static void beforeAll() {
		Security.addProvider(new BouncyCastleProvider());	// Register BC provider, required if making direct or indirect JCA/JCE calls to BC
	}

	@AfterAll static void afterAll() {
		Security.removeProvider("BC");	// Remove BC provider, so other test classes can add and remove BC provider
	}

	@Test void testCreate() throws Exception {
		final List<KeyStoreManager> caChain = new ArrayList<>();
		final List<KeyStoreManager> endEntities = new ArrayList<>();

		final int numCa = 3;
		KeyStoreManager ksmIssuer = null;
		for (int i = 0; i < numCa; i++) {
			final char[] password = ("CaPwd"+i).toCharArray();
			// Example: numCa=3 => Root pathLenConstraint=2, Intermediate pathLenConstraint=1, Issuing pathLenConstraint=1
			final int pathLenConstraint = numCa - 1 - i;
			final Extension[] caExtensions = new Extension[] {
					new Extension(Extension.basicConstraints, true, new BasicConstraints(pathLenConstraint).toASN1Primitive().getEncoded()),
					new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign).toASN1Primitive().getEncoded())
				};
			final KeyStoreManager ksmSubject = KeyStoreManager.create(ksmIssuer, "DC=CA" + i, "EC", password, password, caExtensions, null);
			caChain.add(ksmSubject);
			ksmIssuer = ksmSubject;
		}
		Collections.reverse(caChain);

		final int numEndEntities = 2;
		for (int i = 0; i < numEndEntities; i++) {
			final String email = "EndEntity"+i+"@example.com";
			final char[] password = ("EndEntityPwd"+i).toCharArray();
			final Extension[] endEntityExtensions = new Extension[] {
					new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
					new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}).toASN1Primitive().getEncoded()),
					new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.rfc822Name, email)).build().toASN1Primitive().getEncoded())
				};
			final KeyStoreManager ksmSubject = KeyStoreManager.create(ksmIssuer, "CN=EndEntity"+i+"+serialNumber=" + i, "EC", password, password, endEntityExtensions, null);
			endEntities.add(ksmSubject);
		}
	}
}
