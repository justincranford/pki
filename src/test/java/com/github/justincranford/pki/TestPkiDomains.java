package com.github.justincranford.pki;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assume.assumeNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import javax.net.ssl.X509ExtendedTrustManager;
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
import org.junit.rules.ExpectedException;
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

	record PkiDomain(List<KeyStoreManager> caChain, List<KeyStoreManager> endEntities) {}

	@BeforeAll static void beforeAll() {
		Security.addProvider(new BouncyCastleProvider());	// Register BC provider, required if making direct or indirect JCA/JCE calls to BC
	}

	@AfterAll static void afterAll() {
		Security.removeProvider("BC");	// Remove BC provider, so other test classes can add and remove BC provider
	}

	@Test void testCreate() throws Exception {
		final PkiDomain pkiDomain0 = extracted(0, 1); // numCa=0, numEndEntities=1
		final PkiDomain pkiDomain1 = extracted(1, 2); // numCa=1, numEndEntities=2
		final PkiDomain pkiDomain2 = extracted(2, 2); // numCa=2, numEndEntities=2
		final PkiDomain pkiDomain3 = extracted(3, 2); // numCa=3, numEndEntities=2

		final TrustManagerFactory tmf1 = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		final Certificate caCertificate = pkiDomain1.caChain.get(pkiDomain1.caChain.size()-1).entry().getCertificateChain()[0];
		final KeyStore trustStore = KeyStore.getInstance("JCEKS");
		trustStore.load(null);
		trustStore.setCertificateEntry("cert", caCertificate);
		tmf1.init(trustStore);
		TrustManager[] trustManagers1 = tmf1.getTrustManagers();
		final X509ExtendedTrustManager trustManager1 = (X509ExtendedTrustManager) trustManagers1[0];

		// Certs in pkiDomain1 are trusted by pkiDomain1
		final X509Certificate[] endEntityCertificateChain1 = (X509Certificate[]) pkiDomain1.endEntities.get(0).entry().getCertificateChain();
		trustManager1.checkClientTrusted(endEntityCertificateChain1, "ECDHE_ECDSA"); // From EndEntityChecker.KU_SERVER_SIGNATURE
		trustManager1.checkServerTrusted(endEntityCertificateChain1, "ECDHE_ECDSA");

		// Self-signed certs in pkiDomain0 are not trusted by pkiDomain1
		final Exception exception0 = assertThrows(Exception.class, () -> {
			final X509Certificate[] endEntityCertificateChain0 = (X509Certificate[]) pkiDomain0.endEntities.get(0).entry().getCertificateChain();
			trustManager1.checkClientTrusted(endEntityCertificateChain0, "ECDHE_ECDSA");
	    });
	    assertThat(exception0.getMessage(), is(equalTo("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target")));

		// Certs in pkiDomain2 are not trusted by pkiDomain1
	    final Exception exception2 = assertThrows(Exception.class, () -> {
	    	final X509Certificate[] endEntityCertificateChain2 = (X509Certificate[]) pkiDomain2.endEntities.get(0).entry().getCertificateChain();
			trustManager1.checkClientTrusted(endEntityCertificateChain2, "ECDHE_ECDSA");
	    });
	    assertThat(exception2.getMessage(), is(equalTo("PKIX path validation failed: java.security.cert.CertPathValidatorException: signature check failed")));

		// Certs in pkiDomain3 are not trusted by pkiDomain1
	    final Exception exception3 = assertThrows(Exception.class, () -> {
	    	final X509Certificate[] endEntityCertificateChain3 = (X509Certificate[]) pkiDomain3.endEntities.get(0).entry().getCertificateChain();
			trustManager1.checkClientTrusted(endEntityCertificateChain3, "ECDHE_ECDSA");
	    });
	    assertThat(exception3.getMessage(), is(equalTo("PKIX path validation failed: java.security.cert.CertPathValidatorException: signature check failed")));
	}

	private PkiDomain extracted(final int numCa, final int numEndEntities) throws IOException, Exception {
		final List<KeyStoreManager> caChain = new ArrayList<>(numCa);
		KeyStoreManager ksmIssuer = null;
		for (int i = 0; i < numCa; i++) {
			// Example: numCa=3 => Root CA pathLenConstraint=2, Intermediate CA pathLenConstraint=1, Issuing CA pathLenConstraint=0
			final Extension[] caExtensions = createCaExtensions(numCa - 1 - i);
			final char[] password = ("CaPwd"+i).toCharArray();
			final KeyStoreManager ksmSubject = KeyStoreManager.create(ksmIssuer, "DC=CA" + i, "EC", password, password, caExtensions, null);
			caChain.add(ksmSubject);
			ksmIssuer = ksmSubject; // use the subject CA as the issuer CA in the next loop iteration
		}
		Collections.reverse(caChain);

		final List<KeyStoreManager> endEntities = new ArrayList<>(numEndEntities);
		for (int i = 0; i < numEndEntities; i++) {
			final Extension[] endEntityExtensions = createClientEndEntityExtensionsWithEmail("EndEntity"+i+"@example.com");
			final char[] password = ("EndEntityPwd"+i).toCharArray();
			final KeyStoreManager ksmSubject = KeyStoreManager.create(ksmIssuer, "CN=EndEntity"+i+"+serialNumber=" + i, "EC", password, password, endEntityExtensions, null);
			endEntities.add(ksmSubject);
		}
		return new PkiDomain(caChain, endEntities);
	}

	private Extension[] createCaExtensions(final int pathLenConstraint) throws IOException {
		return new Extension[] {
			new Extension(Extension.basicConstraints, true, new BasicConstraints(pathLenConstraint).toASN1Primitive().getEncoded()),
			new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign).toASN1Primitive().getEncoded())
		};
	}

	private Extension[] createClientEndEntityExtensionsWithEmail(final String email) throws IOException {
		return new Extension[] {
			new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
			new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}).toASN1Primitive().getEncoded()),
			new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.rfc822Name, email)).build().toASN1Primitive().getEncoded())
		};
	}
}
