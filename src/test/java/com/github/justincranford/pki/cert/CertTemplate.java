package com.github.justincranford.pki.cert;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x509.Extensions;

public record CertTemplate(String name, Extensions defaultExtensions, Function<Extensions,Extensions> filterInputExtensions) {
	protected static final Logger LOG = Logger.getLogger(CertTemplate.class.getCanonicalName());

	private static final ConcurrentHashMap<String,Object> UNIQUE_NAMES = new ConcurrentHashMap<>();

	public CertTemplate(String name, Extensions defaultExtensions, Function<Extensions,Extensions> filterInputExtensions) {
		if (UNIQUE_NAMES.put(name, name) != null) {
			throw new IllegalArgumentException("Names must be unique. Name " + name + " is already in use.");
		}
		this.name = name;
		this.defaultExtensions = defaultExtensions;
		this.filterInputExtensions = filterInputExtensions;
	}

	public static final CertTemplate PROFILE_UNLIMITED_CA = new CertTemplate("Unlimited CA",
		ExtensionUtil.extensions(ExtensionUtil.EXTENSION_BC_UNLIMITED, ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN),
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertTemplate PROFILE_ROOT_CA_1 = new CertTemplate("Root CA",
		ExtensionUtil.extensions(ExtensionUtil.EXTENSION_BC_1, ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN),
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertTemplate PROFILE_SUBORDINATE_CA_0 = new CertTemplate("Subordinate CA",
		ExtensionUtil.extensions(ExtensionUtil.EXTENSION_BC_0, ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN),
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertTemplate PROFILE_HTTPS_CLIENT_SERVER = new CertTemplate("HTTPS Client Server",
		ExtensionUtil.extensions(ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_CLIENT_SERVER),
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static final CertTemplate PROFILE_HTTPS_CLIENT = new CertTemplate("HTTPS Client",
		ExtensionUtil.extensions(ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_CLIENT),
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static final CertTemplate PROFILE_HTTPS_SERVER = new CertTemplate("HTTPS Server",
		ExtensionUtil.extensions(ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_SERVER),
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static CertTemplate createCaProfile(final String name, final int pathLenConstraint) {
		final CertTemplate caProfile = new CertTemplate(name,
			ExtensionUtil.extensions(ExtensionUtil.bcExtension(pathLenConstraint), ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN),
			ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
		);
		return caProfile;
	}
}