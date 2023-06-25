import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.operator.ContentSigner;


import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;

public class CertificateBuilder {

    public byte[] generateCert(RSAPublicKey publicKey, RSAPrivateKey privateKey, String cardNumber)
            throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {

        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        // Create the subject and issuer names
        X500Name subject = new X500Name("CN=John Doe, OU=Engineering, O=My Company, C=US");
        X500Name issuer = subject; // Use the same name for issuer and subject in this example

        // Set the certificate validity dates
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); // Valid for 1 year

        // Create the X509v3 certificate generator
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                publicKey);

        ASN1EncodableVector cardNumberValues = new ASN1EncodableVector();
        cardNumberValues.add(new DERPrintableString(cardNumber));
        ASN1Set cardNumberSet = new DERSet(cardNumberValues);

        ASN1EncodableVector cardNameValues = new ASN1EncodableVector();
        cardNameValues.add(new DERUTF8String(cardNumber));
        ASN1Set cardNameSet = new DERSet(cardNameValues);

       // Extension cardNumberExtension = Extension.create(new ASN1ObjectIdentifier("card_number"), false,
                //new DEROctetString(cardNumberSet.getEncoded()));
        //Extension cardNameExtension = Extension.create(new ASN1ObjectIdentifier("card_name"), false,
                //new DEROctetString(cardNameSet.getEncoded()));

        


        ASN1ObjectIdentifier cardNumberOid = new ASN1ObjectIdentifier("1.2.3.4.5"); // Custom OID for card_number
        ASN1EncodableVector cardNumberValuesTry = new ASN1EncodableVector();
        cardNumberValuesTry.add(new DERPrintableString("1234567"));
        ASN1Set cardNumberSetTry = new DERSet(cardNumberValuesTry);

        // Create the attribute extension
        Extension cardNumberExtensionTry = new Extension(cardNumberOid, false, cardNumberSetTry.getEncoded());

        // Add the extension to the certificate builder
        certBuilder.addExtension(cardNumberExtensionTry);







       // certBuilder.addExtension(cardNumberExtension);
       // certBuilder.addExtension(cardNameExtension);

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
        X509CertificateHolder certificateHolder = certBuilder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

        return certificate.getEncoded();
    }
}
