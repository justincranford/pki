package com.github.justincranford.common;

public class StringUtil {

	public static String hex(final byte[] byteArray) {
	    StringBuffer hexStringBuffer = new StringBuffer();
	    for (int i = 0; i < byteArray.length; i++) {
	        hexStringBuffer.append(byteToHex(byteArray[i]));
	    }
	    return hexStringBuffer.toString();
	}
	public static String byteToHex(final byte num) {
	    char[] hexDigits = new char[2];
	    hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
	    hexDigits[1] = Character.forDigit((num & 0xF), 16);
	    return new String(hexDigits);
	}
}
