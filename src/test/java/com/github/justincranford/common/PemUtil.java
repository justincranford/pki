package com.github.justincranford.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

public class PemUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(PemUtil.class);

    public static void printPem(final String msg, final String pemType, final byte[]... payloads) throws Exception {
        LOGGER.info(msg);
        for (final byte[] payload : payloads) {
            System.out.println("-----BEGIN "+pemType+"-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(payload) + "\n-----END "+pemType+"-----");
        }
    }
}
