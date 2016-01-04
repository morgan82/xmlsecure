/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.globallogic.xmlsec;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globallogic.xmlsec.utils.CertificateUtils;
import org.globallogic.xmlsec.utils.XmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;

/**
 * This sample demonstrates how to decrypt data inside an xml document.
 *
 * @author Vishal Mahajan (Sun Microsystems)
 */
public class Decrypter {

    static org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(
                    Decrypter.class.getName());

    static {
        org.apache.xml.security.Init.init();
    }

    private static Document loadEncryptionDocument() throws Exception {
        String fileName = "build/encryptedInfo.xml";
        // File encryptionFile = new File(fileName);
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><products><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><ds:KeyInfo>\n" +
                "<ds:X509Data>\n" +
                "<ds:X509Certificate>" +
                "MIIDRjCCAq+gAwIBAgIJAPKtgzF3G3qmMA0GCSqGSIb3DQEBBQUAMHYxCzAJBgNVBAYTAkFSMQsw" +
                "CQYDVQQIEwJBUjELMAkGA1UEBxMCTVoxCzAJBgNVBAoTAkdMMQswCQYDVQQLEwJMRzENMAsGA1UE" +
                "AxMESXZhbjEkMCIGCSqGSIb3DQEJARYVaXZhbi5iZWVybGlAZ21haWwuY29tMB4XDTE1MTIyODIx" +
                "MDIwOVoXDTE2MTIyNzIxMDIwOVowdjELMAkGA1UEBhMCQVIxCzAJBgNVBAgTAkFSMQswCQYDVQQH" +
                "EwJNWjELMAkGA1UEChMCR0wxCzAJBgNVBAsTAkxHMQ0wCwYDVQQDEwRJdmFuMSQwIgYJKoZIhvcN" +
                "AQkBFhVpdmFuLmJlZXJsaUBnbWFpbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMHP" +
                "DJ3fWZLFPH9ux2JPEddPhMfVoYiknhKPvOk1JcH268DxFXPwZvEWbxpXQzn6Q7lIwL1APO5HBZpr" +
                "LZGlZruN8TOY3r5RK2+xmORxlLOkUxWbi+yNZUvBABGooAG4vLi/yMhgpbxAQEedaCJ1PuYggKWH" +
                "hIJ5hWwzUS7wfw5HAgMBAAGjgdswgdgwHQYDVR0OBBYEFNQ9aZzT1ZaKJPeGGCWGIko/MQeAMIGo" +
                "BgNVHSMEgaAwgZ2AFNQ9aZzT1ZaKJPeGGCWGIko/MQeAoXqkeDB2MQswCQYDVQQGEwJBUjELMAkG" +
                "A1UECBMCQVIxCzAJBgNVBAcTAk1aMQswCQYDVQQKEwJHTDELMAkGA1UECxMCTEcxDTALBgNVBAMT" +
                "BEl2YW4xJDAiBgkqhkiG9w0BCQEWFWl2YW4uYmVlcmxpQGdtYWlsLmNvbYIJAPKtgzF3G3qmMAwG" +
                "A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAh5fSuBFHm8t1A5EUzIiQH6swPud/MyUfCjqp" +
                "N8vxrjvrecvGWlQjOpusK6OvvHaBii8nfGniOeXG1Fe4GbL2i2PnhdboPpkCIQJV575vra2Q56Xo" +
                "n2lPkTcB+kNYFhMCe/FLrRznrTfgDNqETgLzuUqWixNCl5s21/kL7lBD76w=" +
                "</ds:X509Certificate>\n" +
                "</ds:X509Data>\n" +
                "</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>NX1l4A0qVP5cv2l95dLFQqNrLIsxDTxD1L35XqJbmU2+yTDFEld/Lc2KrdqGadeU1Vu7EzsYdk9j" +
                "iRVgDU7Tnb7wkjnw7xw7oxw27NT4JqTncFu6R2AZqI6qcfH5KDxI/9WBQOEGMZHaBhooMnSd0LBT" +
                "zinUCI1YNq+82iMCSwI=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>wsKjuKBva9YLIOgWSt+XF/fLANCeq6Chm4dVkzSCiRS6TwyHp3nSitt2ylk+M4gLirNAmlxaQyhw" +
                "pdVI88N7+DlVSLT7bZbS7AO7/HWxVmRTOTAdyXpzOswrBqth33m+7rFKCrcOSkbnqn7F3nl0dhTh" +
                "iBJQ/3Gx/mU4tPWW/c9EDvDl+s4rU1ziFq7GoZ8XLB8FEBqApkAZgoajcCmalZrD9mkqwpm3Dte+" +
                "Rn3vRHESsdZzYgDtN5tradGBa+csAx2XzK258mpNckVFUMdQGbR+QBCbPoreZCkHrAV+0NQB4F1y" +
                "XShRnZUWnXFDyVtRZCT5j8esYhojJGVB6aSOpb/6o0lNLOBg/IbRofY5vy7c5/UPGY9FRUu3I5DF" +
                "6F4o5EDB/0kDu7eIMfZYFEY6R6xbxk7N/17Wn3XvkK4Yn9I3SYwUgmh2YXB14pMoisTFKiD/TFdz" +
                "sDeXBWquzOPOKeiLDFOFlrfDHUbiOdaWOl42XQWfNDn4K8qiPveD+KEF/kp+HxLVNWbndddcNiKT" +
                "/nLq01jVCCUB9p8LmE+8GbzOTJi2FpRiAdg8S9mFeGZ/uNqTN7rwZaK16U036eu6sd0EEM5pELZj" +
                "2jlNhaf8DT5TvwhjZ+eS3OI+T+IHDNaLuO+fXNAXKMqq+enmJ8gnWC4qwRjH6Kd8gIIx21EVeQAz" +
                "/U39GBWE0KkbYceN/ode2cNVvqwIAfO7/YG3Rt23aInZjYlWAHXebnRzdrZB7c0TIzYsEc7Y8yWG" +
                "r1YPr+Spz0Qg3gvUgjFAeCP4diFwUR6jmgD68dzwE+hJcZmvpo+wwaByCSWKy8+S875SJZkM+0p7" +
                "/PHp+d0hmfRey0Vb4qiDnPQv9ddD9Rzb4D13i/i66N1hEjns3kK0TxkqM7IwN1WzXzY2h51YGHEn" +
                "mDbO0lDhf1sWZjT7kJ2LttknhXn6NENPerzbNbLY6E2vHvo62VorIBOtKOzbZKzqA6ZisZY9MP+r" +
                "TCsuPThkLNtXPhrdXAe5Vyebqs2A24A3uIf/</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></products>";


        Document document = db.parse(new InputSource(new StringReader(xmlString)));
        //System.out.println(
        //  "Encryption document loaded from " + encryptionFile.toURI().toURL().toString()
        //);
        return document;
    }

    private static SecretKey loadKeyEncryptionKey() throws Exception {
        String fileName = "build/kek";
        String jceAlgorithmName = "DESede";

        File kekFile = new File(fileName);

        DESedeKeySpec keySpec =
                new DESedeKeySpec(JavaUtils.getBytesFromFile(fileName));
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance(jceAlgorithmName);
        SecretKey key = skf.generateSecret(keySpec);

        System.out.println(
                "Key encryption key loaded from " + kekFile.toURI().toURL().toString()
        );

        return key;
    }

    private static void outputDocToFile(Document doc, String fileName) throws Exception {
        File encryptionFile = new File(fileName);
        //   FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(doc);
        // StreamResult result = new StreamResult(f);
        StringWriter writer = new StringWriter();
        //transformer.transform(source, result);
        transformer.transform(new DOMSource(doc.getDocumentElement()),
                new StreamResult(writer));
        System.out.println(writer.toString());
        //f.close();
        /*System.out.println(
            "Wrote document containing encrypted data to " + encryptionFile.toURI().toURL().toString()
        );*/
    }

    /*
        private static void outputDocToFile(Document doc, String fileName) throws Exception {
            File encryptionFile = new File(fileName);
            FileOutputStream f = new FileOutputStream(encryptionFile);

            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(f);
            transformer.transform(source, result);

            f.close();
            System.out.println(
                "Wrote document containing decrypted data to " + encryptionFile.toURI().toURL().toString()
            );
        }
    */
    public static void main(String unused[]) throws Exception {

        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><products><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><ds:KeyInfo>\n" +
                "<ds:X509Data>\n" +
                "<ds:X509Certificate>" +
                "MIIDRjCCAq+gAwIBAgIJAPKtgzF3G3qmMA0GCSqGSIb3DQEBBQUAMHYxCzAJBgNVBAYTAkFSMQsw" +
                "CQYDVQQIEwJBUjELMAkGA1UEBxMCTVoxCzAJBgNVBAoTAkdMMQswCQYDVQQLEwJMRzENMAsGA1UE" +
                "AxMESXZhbjEkMCIGCSqGSIb3DQEJARYVaXZhbi5iZWVybGlAZ21haWwuY29tMB4XDTE1MTIyODIx" +
                "MDIwOVoXDTE2MTIyNzIxMDIwOVowdjELMAkGA1UEBhMCQVIxCzAJBgNVBAgTAkFSMQswCQYDVQQH" +
                "EwJNWjELMAkGA1UEChMCR0wxCzAJBgNVBAsTAkxHMQ0wCwYDVQQDEwRJdmFuMSQwIgYJKoZIhvcN" +
                "AQkBFhVpdmFuLmJlZXJsaUBnbWFpbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMHP" +
                "DJ3fWZLFPH9ux2JPEddPhMfVoYiknhKPvOk1JcH268DxFXPwZvEWbxpXQzn6Q7lIwL1APO5HBZpr" +
                "LZGlZruN8TOY3r5RK2+xmORxlLOkUxWbi+yNZUvBABGooAG4vLi/yMhgpbxAQEedaCJ1PuYggKWH" +
                "hIJ5hWwzUS7wfw5HAgMBAAGjgdswgdgwHQYDVR0OBBYEFNQ9aZzT1ZaKJPeGGCWGIko/MQeAMIGo" +
                "BgNVHSMEgaAwgZ2AFNQ9aZzT1ZaKJPeGGCWGIko/MQeAoXqkeDB2MQswCQYDVQQGEwJBUjELMAkG" +
                "A1UECBMCQVIxCzAJBgNVBAcTAk1aMQswCQYDVQQKEwJHTDELMAkGA1UECxMCTEcxDTALBgNVBAMT" +
                "BEl2YW4xJDAiBgkqhkiG9w0BCQEWFWl2YW4uYmVlcmxpQGdtYWlsLmNvbYIJAPKtgzF3G3qmMAwG" +
                "A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAh5fSuBFHm8t1A5EUzIiQH6swPud/MyUfCjqp" +
                "N8vxrjvrecvGWlQjOpusK6OvvHaBii8nfGniOeXG1Fe4GbL2i2PnhdboPpkCIQJV575vra2Q56Xo" +
                "n2lPkTcB+kNYFhMCe/FLrRznrTfgDNqETgLzuUqWixNCl5s21/kL7lBD76w=" +
                "</ds:X509Certificate>\n" +
                "</ds:X509Data>\n" +
                "</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>NX1l4A0qVP5cv2l95dLFQqNrLIsxDTxD1L35XqJbmU2+yTDFEld/Lc2KrdqGadeU1Vu7EzsYdk9j" +
                "iRVgDU7Tnb7wkjnw7xw7oxw27NT4JqTncFu6R2AZqI6qcfH5KDxI/9WBQOEGMZHaBhooMnSd0LBT" +
                "zinUCI1YNq+82iMCSwI=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>wsKjuKBva9YLIOgWSt+XF/fLANCeq6Chm4dVkzSCiRS6TwyHp3nSitt2ylk+M4gLirNAmlxaQyhw" +
                "pdVI88N7+DlVSLT7bZbS7AO7/HWxVmRTOTAdyXpzOswrBqth33m+7rFKCrcOSkbnqn7F3nl0dhTh" +
                "iBJQ/3Gx/mU4tPWW/c9EDvDl+s4rU1ziFq7GoZ8XLB8FEBqApkAZgoajcCmalZrD9mkqwpm3Dte+" +
                "Rn3vRHESsdZzYgDtN5tradGBa+csAx2XzK258mpNckVFUMdQGbR+QBCbPoreZCkHrAV+0NQB4F1y" +
                "XShRnZUWnXFDyVtRZCT5j8esYhojJGVB6aSOpb/6o0lNLOBg/IbRofY5vy7c5/UPGY9FRUu3I5DF" +
                "6F4o5EDB/0kDu7eIMfZYFEY6R6xbxk7N/17Wn3XvkK4Yn9I3SYwUgmh2YXB14pMoisTFKiD/TFdz" +
                "sDeXBWquzOPOKeiLDFOFlrfDHUbiOdaWOl42XQWfNDn4K8qiPveD+KEF/kp+HxLVNWbndddcNiKT" +
                "/nLq01jVCCUB9p8LmE+8GbzOTJi2FpRiAdg8S9mFeGZ/uNqTN7rwZaK16U036eu6sd0EEM5pELZj" +
                "2jlNhaf8DT5TvwhjZ+eS3OI+T+IHDNaLuO+fXNAXKMqq+enmJ8gnWC4qwRjH6Kd8gIIx21EVeQAz" +
                "/U39GBWE0KkbYceN/ode2cNVvqwIAfO7/YG3Rt23aInZjYlWAHXebnRzdrZB7c0TIzYsEc7Y8yWG" +
                "r1YPr+Spz0Qg3gvUgjFAeCP4diFwUR6jmgD68dzwE+hJcZmvpo+wwaByCSWKy8+S875SJZkM+0p7" +
                "/PHp+d0hmfRey0Vb4qiDnPQv9ddD9Rzb4D13i/i66N1hEjns3kK0TxkqM7IwN1WzXzY2h51YGHEn" +
                "mDbO0lDhf1sWZjT7kJ2LttknhXn6NENPerzbNbLY6E2vHvo62VorIBOtKOzbZKzqA6ZisZY9MP+r" +
                "TCsuPThkLNtXPhrdXAe5Vyebqs2A24A3uIf/</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></products>";

        System.out.println(decriptXml(xmlString,"testaio1.pem"));
    }

    public static String decriptXml(String xmlString, String cert){
        try {
            Document document = XmlUtils.stringToXML(xmlString);
            //Document document = loadEncryptionDocument();

            Element encryptedDataElement =
                    (Element) document.getElementsByTagNameNS(
                            EncryptionConstants.EncryptionSpecNS,
                            EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

            /*
             * Load the key to be used for decrypting the xml data
             * encryption key.
             */
            Security.addProvider(new BouncyCastleProvider());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            Key kek = CertificateUtils.generatePrivateKey(factory, cert);
            //Key kek = loadKeyEncryptionKey();

            String providerName = "BC";

            XMLCipher xmlCipher =
                    XMLCipher.getInstance();
            /*
             * The key to be used for decrypting xml data would be obtained
             * from the keyinfo of the EncrypteData using the kek.
             */
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
            xmlCipher.setKEK(kek);
            /*
             * The following doFinal call replaces the encrypted data with
             * decrypted contents in the document.
             */
            xmlCipher.doFinal(document, encryptedDataElement);

            return XmlUtils.xmlToString(document);

        }catch (Exception e){
            return null;
        }

    }
}
