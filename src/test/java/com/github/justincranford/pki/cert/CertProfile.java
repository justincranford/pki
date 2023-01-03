package com.github.justincranford.pki.cert;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x509.Extension;
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

	public static final CertProfile PROFILE_ROOT_CA = new CertProfile("Root CA", 100,
		new Extensions(new Extension[] { ExtensionUtil.EXTENSION_BC_1, ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN }),
		(inputExtensions) -> { return ExtensionUtil.filterExtensions(inputExtensions, List.of(Extension.issuerAlternativeName)); }
	);

	public static final CertProfile PROFILE_SUBORDINATE_CA = new CertProfile("Subordinate CA", 100,
		new Extensions(new Extension[] { ExtensionUtil.EXTENSION_BC_0, ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN }),
		(inputExtensions) -> { return ExtensionUtil.filterExtensions(inputExtensions, List.of(Extension.issuerAlternativeName)); }
	);

	public static final CertProfile PROFILE_HTTPS_CLIENT = new CertProfile("HTTPS Client", 50,
		new Extensions(new Extension[] { ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_CLIENTAUTH }),
		(inputExtensions) -> { return ExtensionUtil.filterExtensions(inputExtensions, List.of(Extension.subjectAlternativeName)); }
	);

	public static final CertProfile PROFILE_HTTPS_SERVER = new CertProfile("HTTPS Server", 50,
		new Extensions(new Extension[] { ExtensionUtil.EXTENSION_KU_DIGITALSIGNATURE, ExtensionUtil.EXTENSION_EKU_SERVERAUTH }),
		(inputExtensions) -> { return ExtensionUtil.filterExtensions(inputExtensions, List.of(Extension.subjectAlternativeName)); }
	);

	public static CertProfile createCaProfile(final String name, final int pwdLength, final int pathLenConstraint) {
		final CertProfile caProfile = new CertProfile(name, pwdLength,
			new Extensions(new Extension[] { ExtensionUtil.createBcExtension(pathLenConstraint), ExtensionUtil.EXTENSION_KU_KEYCERTSIGN_CRLSIGN }),
			(inputExtensions) -> { return ExtensionUtil.filterExtensions(inputExtensions, List.of(Extension.issuerAlternativeName)); }
		);
		return caProfile;
	}
}