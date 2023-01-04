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
		ExtensionUtil.EXTENSIONS_CA_UNLIMITED,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertTemplate PROFILE_ROOT_CA_1 = new CertTemplate("Root CA",
		ExtensionUtil.EXTENSIONS_CA_1,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertTemplate PROFILE_SUBORDINATE_CA_0 = new CertTemplate("Subordinate CA",
		ExtensionUtil.EXTENSIONS_CA_0,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertTemplate PROFILE_HTTPS_CLIENT_SERVER = new CertTemplate("HTTPS Client Server",
		ExtensionUtil.EXTENSIONS_HTTPS_CLIENT_SERVER,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static final CertTemplate PROFILE_HTTPS_CLIENT = new CertTemplate("HTTPS Client",
		ExtensionUtil.EXTENSIONS_HTTPS_CLIENT,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static final CertTemplate PROFILE_HTTPS_SERVER = new CertTemplate("HTTPS Server",
		ExtensionUtil.EXTENSIONS_HTTPS_SERVER,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static CertTemplate createCaProfile(final String name, final int pathLenConstraint) {
		final CertTemplate caProfile = new CertTemplate(name,
			ExtensionUtil.caExtensions(pathLenConstraint),
			ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
		);
		return caProfile;
	}
}