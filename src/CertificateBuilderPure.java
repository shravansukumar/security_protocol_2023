import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import sun.security.x509.*;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;

import java.util.Date;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class CertificateBuilderPure  {

    public byte [] generateCertificate(ECPublicKey publicKey, ECPrivateKey privateKey, String cardNumber, String type)
     throws IOException, CertificateException, CertificateEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        X509CertInfo certInfo = new X509CertInfo();
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000L); // Valid for 1 year

        certInfo.set("validity", new CertificateValidity(startDate, endDate));
        certInfo.set("serialNumber", new CertificateSerialNumber((int) startDate.getTime()));
        certInfo.set("version", new CertificateVersion(CertificateVersion.V3));

        X500Name issuer = new X500Name("CN=self");
        X500Name subject = issuer;

        certInfo.set("issuer", new CertificateIssuerName(issuer));
        certInfo.set("subject", new CertificateSubjectName(subject));
        certInfo.set("key", new CertificateX509Key(publicKey));
        certInfo.set("algorithmID", new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.sha256WithECDSA_oid)));


        ObjectIdentifier cardNumberOid = new ObjectIdentifier("1.2.3");
        byte [] cardNumberBytes = cardNumber.getBytes();
       
       byte [] cardNumberExtensionValue  = createExtensionValue(cardNumberBytes);
       Extension cardNumberExtension = new Extension(cardNumberOid, false, cardNumberExtensionValue);

       byte [] cardTypeExtensionValue = createExtensionValue(type.getBytes());
       Extension cardTypExtension = new Extension(new ObjectIdentifier("1.2.4"), false, cardTypeExtensionValue); // Custom string object id for cardType

        CertificateExtensions extensions = new CertificateExtensions();
        extensions.set("card_no", cardNumberExtension);
        extensions.set("type", cardTypExtension);

        certInfo.set(X509CertInfo.EXTENSIONS, extensions);

        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(privateKey, "SHA256withECDSA");

        return cert.getEncoded();

    }


    private static byte [] createExtensionValue(byte [] value) throws IOException {
        DerOutputStream valueStream = new DerOutputStream();
        valueStream.putOctetString(value);

        //DerOutputStream extensionStream = new DerOutputStream();
        //extensionStream.write(DerValue.tag_Sequence, valueStream);

        return valueStream.toByteArray();
    }
    
}
