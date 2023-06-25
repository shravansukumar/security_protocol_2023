import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import sun.security.x509.*;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

import java.util.Date;
import java.util.Vector;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class CertificateBuilderPure  {

    public byte [] generateCertificate(RSAPublicKey publicKey, RSAPrivateKey privateKey, String cardNumber)
     throws IOException, CertificateException, CertificateEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        X509CertInfo certInfo = new X509CertInfo();
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000L); // Valid for 1 year


        

        certInfo.set("validity", new CertificateValidity(startDate, endDate));
        certInfo.set("serialNumber", new CertificateSerialNumber((int) startDate.getTime()));
        certInfo.set("version", new CertificateVersion(CertificateVersion.V3));

        X500Name issuer = new X500Name("CN=My CA");
        X500Name subject = new X500Name("CN=My Certificate");

        certInfo.set("issuer", new CertificateIssuerName(issuer));
        certInfo.set("subject", new CertificateSubjectName(subject));
        certInfo.set("key", new CertificateX509Key(publicKey));
        certInfo.set("algorithmID", new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid)));


        ObjectIdentifier cardNumberOid = new ObjectIdentifier("1.2.3.4.5");
        byte [] cardNumberBytes = cardNumber.getBytes();
       
        //Extension[] extensions = new Extension[1];
        //extensions[0] = new Extension(cardNumberOid, false, cardNumberBytes);
        //CertificateExtensions certExtensions = new CertificateExtensions(extensions);

       // Vector<Extension> extensions = new Vector<>();
       // extensions.add(new Extension(cardNumberOid, false, cardNumberBytes));
       // CertificateExtensions certificateExtensions = new CertificateExtensions();
       // certificateExtensions.set("extensions", extensions);
       // certInfo.set("extensions", extensions);


       byte [] cardNumberExtensionValue  = createExtensionValue(cardNumberBytes);
       Extension extension = new Extension(cardNumberOid, false, cardNumberExtensionValue);

        CertificateExtensions extensions = new CertificateExtensions();
        extensions.set("card_number", extension);

        certInfo.set(X509CertInfo.EXTENSIONS, extensions);

        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(privateKey, "SHA256withRSA");

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
