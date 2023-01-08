package com.github.justincranford.pki.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

public class ExtensionUtil {
	record GeneralNameArgs(List<String> dnsNames, List<String> ipAddresses, List<String> emailAddresses, List<String> directoryNames, List<String> uniformResourceIdentifiers) {}

	public static final BasicConstraints BC_UNLIMITED                      = new BasicConstraints(-1);
	public static final BasicConstraints BC_2                              = new BasicConstraints(2);
	public static final BasicConstraints BC_1                              = new BasicConstraints(1);
	public static final BasicConstraints BC_0                              = new BasicConstraints(0);
	public static final KeyUsage         KU_KEYCERTSIGN                    = new KeyUsage(KeyUsage.keyCertSign);
	public static final KeyUsage         KU_CRLSIGN                        = new KeyUsage(KeyUsage.cRLSign);
	public static final KeyUsage         KU_KEYCERTSIGN_CRLSIGN            = new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign);
	public static final ExtendedKeyUsage EKU_ANY                           = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.anyExtendedKeyUsage});
	public static final ExtendedKeyUsage EKU_OCSPSIGNING                   = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_OCSPSigning});
	public static final ExtendedKeyUsage EKU_CODESIGNING                   = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_codeSigning});
	public static final ExtendedKeyUsage EKU_TIMESTAMPING                  = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_timeStamping});

	public static final KeyUsage         KU_DIGITALSIGNATURE               = new KeyUsage(KeyUsage.digitalSignature);
	public static final KeyUsage         KU_KEYAGREEMENT                   = new KeyUsage(KeyUsage.keyAgreement);
	public static final KeyUsage         KU_KEYENCRYPTION                  = new KeyUsage(KeyUsage.keyEncipherment);
	public static final KeyUsage         KU_DIGITALSIGNATURE_KEYAGREEMENT  = new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyAgreement);
	public static final KeyUsage         KU_DIGITALSIGNATURE_KEYENCRYPTION = new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment);
	public static final ExtendedKeyUsage EKU_SERVER                        = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth});
	public static final ExtendedKeyUsage EKU_CLIENT                        = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth});
	public static final ExtendedKeyUsage EKU_CLIENTSERVER                  = new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth});
	public static final GeneralNames     SAN_LOCALHOST                     = generalNames(Map.of(GeneralName.dNSName, "localhost", GeneralName.iPAddress, "127.0.0.1"));

	public static final Extension EXTENSION_BC_UNLIMITED                      = new Extension(Extension.basicConstraints,       true,  encodeNoException(BC_UNLIMITED));
	public static final Extension EXTENSION_BC_2                              = new Extension(Extension.basicConstraints,       true,  encodeNoException(BC_2));
	public static final Extension EXTENSION_BC_1                              = new Extension(Extension.basicConstraints,       true,  encodeNoException(BC_1));
	public static final Extension EXTENSION_BC_0                              = new Extension(Extension.basicConstraints,       true,  encodeNoException(BC_0));
	public static final Extension EXTENSION_KU_KEYCERTSIGN                    = new Extension(Extension.keyUsage,               true,  encodeNoException(KU_KEYCERTSIGN));
	public static final Extension EXTENSION_KU_CRLSIGN                        = new Extension(Extension.keyUsage,               true,  encodeNoException(KU_CRLSIGN));
	public static final Extension EXTENSION_KU_KEYCERTSIGN_CRLSIGN            = new Extension(Extension.keyUsage,               true,  encodeNoException(KU_KEYCERTSIGN_CRLSIGN));

	public static final Extension EXTENSION_KU_DIGITALSIGNATURE               = new Extension(Extension.keyUsage,               false, encodeNoException(KU_DIGITALSIGNATURE));
	public static final Extension EXTENSION_KU_KEYAGREEMENT                   = new Extension(Extension.keyUsage,               false, encodeNoException(KU_KEYAGREEMENT));
	public static final Extension EXTENSION_KU_KEYENCRYPTION                  = new Extension(Extension.keyUsage,               false, encodeNoException(KU_KEYENCRYPTION));
	public static final Extension EXTENSION_KU_DIGITALSIGNATURE_KEYAGREEMENT  = new Extension(Extension.keyUsage,               false, encodeNoException(KU_DIGITALSIGNATURE_KEYAGREEMENT));
	public static final Extension EXTENSION_KU_DIGITALSIGNATURE_KEYENCRYPTION = new Extension(Extension.keyUsage,               false, encodeNoException(KU_DIGITALSIGNATURE_KEYENCRYPTION));

	public static final Extension EXTENSION_EKU_ANY                           = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_ANY));
	public static final Extension EXTENSION_EKU_OCSPSIGNING                   = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_OCSPSIGNING));
	public static final Extension EXTENSION_EKU_CODESIGNING                   = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_CODESIGNING));
	public static final Extension EXTENSION_EKU_TIMESTAMPING                  = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_TIMESTAMPING));

	public static final Extension EXTENSION_EKU_SERVER                        = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_SERVER));
	public static final Extension EXTENSION_EKU_CLIENT                        = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_CLIENT));
	public static final Extension EXTENSION_EKU_CLIENT_SERVER                 = new Extension(Extension.extendedKeyUsage,       false, encodeNoException(EKU_CLIENTSERVER));
	
	public static final Extension EXTENSION_SAN_LOCALHOST                     = new Extension(Extension.subjectAlternativeName, false, encodeNoException(SAN_LOCALHOST));

	public static final Extension[] EXTENSION_LIST_EMPTY = new Extension[0];
	public static final Extensions EXTENSIONS_EMPTY = new Extensions(EXTENSION_LIST_EMPTY);

	public static final Function<Extensions, Extensions> FILTER_EXTENSIONS_LAMBDA_CA = filterExtensionsLambda(List.of(Extension.issuerAlternativeName));
	public static final Function<Extensions, Extensions> FILTER_EXTENSIONS_LAMBDA_END_ENTITY = filterExtensionsLambda(List.of(Extension.subjectAlternativeName));

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static BasicConstraints bc(final int pathLenConstraint) {
		return new BasicConstraints(pathLenConstraint);
	}
	public static KeyUsage ku(final int usages) {
		return new KeyUsage(usages);
	}
	public static ExtendedKeyUsage eku(final List<KeyPurposeId> keyPurposeIds) {
		return new ExtendedKeyUsage(keyPurposeIds.toArray(new KeyPurposeId[0]));
	}
	public static GeneralNames generalNames(final List<GeneralName> generalNameList) {
		final GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
		for (final GeneralName generalName : generalNameList) {
			generalNamesBuilder.addName(generalName);
		}
		return generalNamesBuilder.build();
	}
	public static GeneralNames generalNames(final Map<Integer,String> map) {
		return generalNames(generalNameList(map));
	}
	public static SubjectKeyIdentifier ski(final byte[] keyid) {
		return new SubjectKeyIdentifier(keyid);
	}
	public static AuthorityKeyIdentifier aki(final byte[] keyid, final GeneralNames generalNames, final BigInteger serialNumber) {
		return new AuthorityKeyIdentifier(keyid, generalNames, serialNumber);
	}
	public static AuthorityKeyIdentifier aki(final byte[] keyid, final Map<Integer,String> map, final BigInteger serialNumber) {
		return new AuthorityKeyIdentifier(keyid, generalNames(map), serialNumber);
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static Extension bcExtension(final int pathLenConstraint) {
		return new Extension(Extension.basicConstraints, true, encodeNoException(bc(pathLenConstraint)));
	}
	public static Extension kuExtension(final int usages) {
		return new Extension(Extension.keyUsage, false, encodeNoException(ku(usages)));
	}
	public static Extension ekuExtension(final List<KeyPurposeId> keyPurposeIds) {
		return new Extension(Extension.extendedKeyUsage, false, encodeNoException(eku(keyPurposeIds)));
	}
	public static Extension sanExtension(final Map<Integer,String> map) {
		return new Extension(Extension.subjectAlternativeName, false, encodeNoException(generalNames(map)));
	}
	public static Extension ianExtension(final Map<Integer,String> map) {
		return new Extension(Extension.issuerAlternativeName, false, encodeNoException(generalNames(map)));
	}
	public static Extension skiExtension(final byte[] keyid) {
		return new Extension(Extension.subjectKeyIdentifier, false, encodeNoException(ski(keyid)));
	}
	public static Extension akiExtension(final byte[] keyid, final Map<Integer,String> map, final BigInteger serialNumber) {
		return new Extension(Extension.authorityKeyIdentifier, false, encodeNoException(aki(keyid, map, serialNumber)));
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static Extensions extensions(final Extension... extensionList) {
		return new Extensions(extensionList);
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	private static byte[] encode(final ASN1Object asn1Object) throws IOException {
		return asn1Object.toASN1Primitive().getEncoded();
	}
	private static byte[] encodeNoException(final ASN1Object asn1Object) {
		try {
			return encode(asn1Object);
		} catch(IOException e) {
			return null;
		}
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static Function<Extensions, Extensions> filterExtensionsLambda(final List<ASN1ObjectIdentifier> oids) {
		return (inputExtensions) -> { 
			if (inputExtensions == null) {
				return EXTENSIONS_EMPTY;
			}
			final List<Extension> extensionsList = oids.stream().map(o -> inputExtensions.getExtension(o)).filter(e -> e != null).toList();
			if (extensionsList.isEmpty()) {
				return EXTENSIONS_EMPTY;
			}
			return new Extensions(extensionsList.toArray(EXTENSION_LIST_EMPTY));
		};
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static Map<Integer, String> createGeneralNameMap(final List<String> dnsNames, final List<String> ipAddresses) {
		final Map<Integer,String> map = new LinkedHashMap<>();
		dnsNames.forEach((d) -> { map.put(GeneralName.dNSName, d); });
		ipAddresses.forEach((d) -> { map.put(GeneralName.iPAddress, d); });
		return map;
	}
	public static List<GeneralName> generalNameList(final Map<Integer,String> map) {
		final List<GeneralName> generalNameList = new ArrayList<>();
		for (final Map.Entry<Integer,String> entry : map.entrySet()) {
			generalNameList.add(new GeneralName(entry.getKey().intValue(), entry.getValue()));
		}
		return generalNameList;
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static List<GeneralName> generalNameListDnsName(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.dNSName, e)).toList();
	}
	public static List<GeneralName> generalNameListIpAddress(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.iPAddress, e)).toList();
	}
	public static List<GeneralName> generalNameListDirectoryNames(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.directoryName, e)).toList();
	}
	public static List<GeneralName> generalNameListEmailAddress(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.rfc822Name, e)).toList();
	}
	public static List<GeneralName> generalNameListUniformResourceIdentifier(final List<String> list) {
		return list.stream().map(e -> new GeneralName(GeneralName.uniformResourceIdentifier, e)).toList();
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}