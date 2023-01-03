package com.github.justincranford.pki.cert;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

public class ExtensionUtil {

	public static final BasicConstraints BC_UNLIMITED           = new BasicConstraints(-1);
	public static final BasicConstraints BC_0                   = new BasicConstraints(0);
	public static final BasicConstraints BC_1                   = new BasicConstraints(1);
	public static final BasicConstraints BC_2                   = new BasicConstraints(2);
	public static final KeyUsage         KU_KEYCERTSIGN_CRLSIGN = new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign);
	public static final KeyUsage         KU_DIGITALSIGNATURE    = new KeyUsage(KeyUsage.digitalSignature);
	public static final ExtendedKeyUsage EKU_CLIENTAUTH         = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth});
	public static final ExtendedKeyUsage EKU_SERVERAUTH         = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth});

	public static final Extension EXTENSION_BC_UNLIMITED           = new Extension(Extension.basicConstraints, true,  encodeNoException(BC_UNLIMITED));
	public static final Extension EXTENSION_BC_0                   = new Extension(Extension.basicConstraints, true,  encodeNoException(BC_0));
	public static final Extension EXTENSION_BC_1                   = new Extension(Extension.basicConstraints, true,  encodeNoException(BC_1));
	public static final Extension EXTENSION_BC_2                   = new Extension(Extension.basicConstraints, true,  encodeNoException(BC_2));
	public static final Extension EXTENSION_KU_KEYCERTSIGN_CRLSIGN = new Extension(Extension.keyUsage,         true,  encodeNoException(KU_KEYCERTSIGN_CRLSIGN));
	public static final Extension EXTENSION_KU_DIGITALSIGNATURE    = new Extension(Extension.keyUsage,         true,  encodeNoException(KU_DIGITALSIGNATURE));
	public static final Extension EXTENSION_EKU_CLIENTAUTH         = new Extension(Extension.extendedKeyUsage, false, encodeNoException(EKU_CLIENTAUTH));
	public static final Extension EXTENSION_EKU_SERVERAUTH         = new Extension(Extension.extendedKeyUsage, false, encodeNoException(EKU_SERVERAUTH));

	public static final Extension[] EXTENSION_LIST_EMPTY = new Extension[0];
	public static final Extensions EXTENSIONS_EMPTY = new Extensions(EXTENSION_LIST_EMPTY);

	public static Extension createBcExtension(final int pathLenConstraint) {
		return new Extension(Extension.basicConstraints, true, encodeNoException(new BasicConstraints(pathLenConstraint)));
	}
	public Extension createSanExtension(final List<GeneralName>... generalNameLists) {
		return new Extension(Extension.subjectAlternativeName, false, encodeNoException(createGeneralNames(generalNameLists)));
	}

	private GeneralNames createGeneralNames(final List<GeneralName>... generalNameLists) {
		final GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
		for (final List<GeneralName> generalNameList : generalNameLists) {
			for (final GeneralName generalName : generalNameList) {
				generalNamesBuilder.addName(generalName);
			}
		}
		return generalNamesBuilder.build();
	}

	public static List<GeneralName> dnsNamesToGeneralNameList(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.dNSName, e)).toList();
	}
	public static List<GeneralName> ipAddressesToGeneralNameList(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.iPAddress, e)).toList();
	}
	public static List<GeneralName> directoryNamesToGeneralNameList(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.directoryName, e)).toList();
	}
	public static List<GeneralName> emailAddressesToGeneralNameList(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.rfc822Name, e)).toList();
	}
	public static List<GeneralName> uniformResourceIdentifiersToGeneralNameList(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.uniformResourceIdentifier, e)).toList();
	}

	private static byte[] encodeNoException(final ASN1Object asn1Object) {
		try {
			return asn1Object.toASN1Primitive().getEncoded();
		} catch(IOException e) {
			return null;
		}
	}

	public static Extensions filterExtensions(final Extensions inputExtensions, final List<ASN1ObjectIdentifier> oids) {
		if (inputExtensions == null) {
			return ExtensionUtil.EXTENSIONS_EMPTY;
		}
		return new Extensions(oids.stream().map(o -> inputExtensions.getExtension(o)).filter(e -> e != null).toList().toArray(ExtensionUtil.EXTENSION_LIST_EMPTY));
	}

	public static Extensions createCaExtensions(final int pathLenConstraint) throws IOException {
		return new Extensions(new Extension[] {
			new Extension(Extension.basicConstraints, true, new BasicConstraints(pathLenConstraint).toASN1Primitive().getEncoded()),
			new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign).toASN1Primitive().getEncoded())
		});
	}

	public static Extensions createClientServerEndEntityExtensionsWithEmail(final String email) throws IOException {
		return new Extensions(new Extension[] {
			new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).toASN1Primitive().getEncoded()),
			new Extension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}).toASN1Primitive().getEncoded()),
			new Extension(Extension.subjectAlternativeName, false, new GeneralNamesBuilder().addName(new GeneralName(GeneralName.rfc822Name, email)).build().toASN1Primitive().getEncoded())
		});
	}
}