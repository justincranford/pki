package com.github.justincranford.common;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.OutputEncryptor;

import java.security.*;
import java.security.cert.X509Certificate;

public class CmsUtil {

    public static byte[] encryptCMSEnvelopedData(
            final byte[] clearBytes,
            final X509Certificate recipientCertificate,
            final X509Certificate senderCertificate,
            final PrivateKey senderPrivateKey
    ) throws Exception {
        // Inner encryption (AES-256-CBC)
        final OutputEncryptor cmsContentEncryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("SunJCE").build();
        // Outer encryption or encryptions (KTRI for RSA, KARI for EC)
        final RecipientInfoGenerator recipientInfoGenerator;
        if (recipientCertificate.getPublicKey().getAlgorithm().equals("RSA")) {
            recipientInfoGenerator = new JceKeyTransRecipientInfoGenerator(recipientCertificate).setProvider("SunJCE");
        } else {
            // TODO Fix for RSA sender EC recipient
            recipientInfoGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, senderPrivateKey, senderCertificate.getPublicKey(), CMSAlgorithm.AES256_WRAP).setProvider("BC");
            ((JceKeyAgreeRecipientInfoGenerator) recipientInfoGenerator).addRecipient(recipientCertificate);
        }
        // Generate
        final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        cmsEnvelopedDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator); // outer encryption(s)
        final CMSTypedData cmsContent = new CMSProcessableByteArray(clearBytes);
        final CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(cmsContent, cmsContentEncryptor); // inner encryption
        final byte[] cmsEnvelopedDataBytes = cmsEnvelopedData.getEncoded();
        // Print
        PemUtil.printPem("Payload", "CMS", cmsEnvelopedDataBytes);
        return cmsEnvelopedDataBytes;
    }

    public static byte[] decryptCmsEnvelopedData(
            final byte[] cmsEnvelopedDataBytes,
            final X509Certificate recipientCertificate,
            final PrivateKey recipientPrivateKey,
            final Provider recipientKeyStoreProvider
    ) throws Exception {
        // Outer decryption
        final RecipientId recipientId;
        final Recipient recipient;
        if (recipientCertificate.getPublicKey().getAlgorithm().equals("RSA")) {
            recipientId = new JceKeyTransRecipientId(recipientCertificate);
            recipient = new JceKeyTransEnvelopedRecipient(recipientPrivateKey).setProvider(recipientKeyStoreProvider);
        } else {
            recipientId = new JceKeyAgreeRecipientId(recipientCertificate);
            recipient = new JceKeyAgreeEnvelopedRecipient(recipientPrivateKey).setProvider(recipientKeyStoreProvider);
        }
        // Decrypt outer KEK to get inner DEK, and use inner DEK to decrypt the data
        final CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(cmsEnvelopedDataBytes);
        final RecipientInformationStore recipientInformationStore = cmsEnvelopedData.getRecipientInfos();
        final RecipientInformation recipientInformation = recipientInformationStore.get(recipientId); // Null if expected RecipientId not found
        final byte[] decryptedData = recipientInformation.getContent(recipient);
        return decryptedData;
    }
}
