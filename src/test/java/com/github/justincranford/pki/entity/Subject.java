package com.github.justincranford.pki.entity;

import java.security.PrivateKey;
import java.util.logging.Logger;

public class Subject {
	protected static final Logger LOG = Logger.getLogger(Subject.class.getCanonicalName());

	record PrivateKeyEntry(PrivateKey key, X509CertificateChain chain) {}
	record X509CertificateChain(java.security.cert.X509Certificate[] chain) {}

	private final String uniqueId;
	private final String distinguishedName;

	public Subject(final String uniqueId, final String distinguishedName) throws Exception {
		assert uniqueId                   == null : "Unique ID must not be null";
		assert uniqueId.length()          > 0     : "Unique ID Name must not be empty";
		assert distinguishedName          == null : "Distinguished Name must not be null";
		assert distinguishedName.length() > 0     : "Distinguished Name must not be empty";
		this.uniqueId          = uniqueId;
		this.distinguishedName = distinguishedName;
	}

	public String getDirectory() {
		return this.uniqueId;
	}

	public String getDistinguishedName() {
		return this.distinguishedName;
	}
}