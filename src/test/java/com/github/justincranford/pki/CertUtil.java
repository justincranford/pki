package com.github.justincranford.pki;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Root CA, Sub CA, Cross-cert, Client/Server End Entity, Client/Server self-signed, etc
public class CertUtil {
	@SuppressWarnings("unused")
	private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreManager.class);

	public static X509Certificate createCert(
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
}
