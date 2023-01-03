package com.github.justincranford.pki.cert;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x509.Extensions;

public record CertProfile(String name, int pwdLength, Extensions defaultExtensions, Function<Extensions,Extensions> filterInputExtensions) {
	protected static final Logger LOG = Logger.getLogger(CertProfile.class.getCanonicalName());

	private static final ConcurrentHashMap<String,Object> NAMES = new ConcurrentHashMap<>();

	public CertProfile(String name, int pwdLength, Extensions defaultExtensions, Function<Extensions,Extensions> filterInputExtensions) {
		if (NAMES.put(name, name) != null) {
			throw new IllegalArgumentException("Names must be unique. Name " + name + " is already in use.");
		}
		this.name = name;
		this.pwdLength = pwdLength;
		this.defaultExtensions = defaultExtensions;
		this.filterInputExtensions = filterInputExtensions;
	}

	public static final CertProfile PROFILE_UNLIMITED_CA = new CertProfile("Unlimited CA", 100,
		ExtensionUtil.EXTENSIONS_CA_UNLIMITED,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertProfile PROFILE_ROOT_CA_1 = new CertProfile("Root CA", 100,
		ExtensionUtil.EXTENSIONS_CA_1,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertProfile PROFILE_SUBORDINATE_CA_0 = new CertProfile("Subordinate CA", 100,
		ExtensionUtil.EXTENSIONS_CA_0,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
	);

	public static final CertProfile PROFILE_HTTPS_CLIENT = new CertProfile("HTTPS Client", 50,
		ExtensionUtil.EXTENSIONS_HTTPS_CLIENT,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static final CertProfile PROFILE_HTTPS_SERVER = new CertProfile("HTTPS Server", 50,
		ExtensionUtil.EXTENSIONS_HTTPS_SERVER,
		ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_END_ENTITY
	);

	public static CertProfile createCaProfile(final String name, final int pwdLength, final int pathLenConstraint) {
		final CertProfile caProfile = new CertProfile(name, pwdLength,
			ExtensionUtil.caExtensions(pathLenConstraint),
			ExtensionUtil.FILTER_EXTENSIONS_LAMBDA_CA
		);
		return caProfile;
	}
}