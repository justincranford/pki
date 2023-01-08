package com.github.justincranford.pki.experimental;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.CDL;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@DisplayName("Test Policy")
class TestPolicy {
	private static final Logger LOGGER = LoggerFactory.getLogger(TestPolicy.class);

	@Test
	public void testJsonObject() {
		final JSONObject policy = new JSONObject();
		policy.put("issuer", "DC=example.com");
		policy.put("validityPeriod", "13m");
		policy.put("allowedEcCurves", List.of("P256", "P384", "P521"));
		LOGGER.info("CA Cert Template Policy: \n" + policy.toString(1));
	}

	@Test
	public void testMap() {
		final Map<String, Object> map = new HashMap<>();
		map.put("issuer", "DC=example.com");
		map.put("validityPeriod", "13m");
		map.put("allowedEcCurves", List.of("P256", "P384", "P521"));
		final JSONObject policy = new JSONObject(map);
		LOGGER.info("CA Cert Template Policy: \n" + policy.toString(1));
	}

	@Test
	public void testBean() {
		final PolicyBean bean = new PolicyBean("DC=example.com", "13m");
		final JSONObject policy = new JSONObject(bean);
		policy.put("allowedEcCurves", List.of("P256", "P384", "P521"));
		LOGGER.info("CA Cert Template Policy: \n" + policy.toString(1));
	}

	@Test
	public void testParse() {
		final JSONTokener tokener = new JSONTokener("P256, P384, P521");
		final JSONArray allowedEcCurves = CDL.rowToJSONArray(tokener);
		LOGGER.info(allowedEcCurves.toString());
	}

	public static class PolicyBean implements java.io.Serializable {
		private static final long serialVersionUID = 1L;

		private String issuer = null;
		private String validityPeriod = null;

		public PolicyBean(String issuer, String validityPeriod) {
			this.issuer = issuer;
			this.validityPeriod = validityPeriod;
		}

		public void setIssuer(final String issuer) {
			this.issuer = issuer;
		}

		public String getIssuer() {
			return issuer;
		}

		public void setValidityPeriod(final String validityPeriod) {
			this.validityPeriod = validityPeriod;
		}

		public String getValidityPeriod() {
			return validityPeriod;
		}
	}
}
