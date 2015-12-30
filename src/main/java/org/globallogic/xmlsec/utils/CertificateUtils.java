package org.globallogic.xmlsec.utils;


import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertificateUtils {

    public final static String CERTIFICATE_DIR = "/certificate/";


    public static PrivateKey generatePrivateKey(KeyFactory factory, String filename)
            throws InvalidKeySpecException, IOException {
        PemFile pemFile = new PemFile(filename);
        byte[] content = pemFile.getPemObject().getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return factory.generatePrivate(privKeySpec);
    }

    public static Certificate getCertificateByName(String filename)
            throws InvalidKeySpecException, IOException, CertificateException {
        InputStream inStream = CertificateUtils.class.getResourceAsStream(CERTIFICATE_DIR + filename);
        //Solo existe un tipo de certifiacado
        //http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
        Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(inStream);
        inStream.close();
        return cert;

    }


}
