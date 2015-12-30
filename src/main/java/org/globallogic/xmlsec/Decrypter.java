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
import java.lang.Exception;import java.lang.String;import java.lang.System;import java.security.Key;
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
                "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><xenc:CipherData><xenc:CipherValue>AvUtTOnitgVZdhsUqTqr3wwcpt5qEIZzQ2HGdAyRVYanZAX7u4O/R7BfuEXuwx+zNpLkfihigNkO" +
                "jLvj1d/gMY9x7xbDSE/zGYDps2CQJfIisGwrhbNCMXwzu7Wf1UbzYp9rF6vf4aXZMkQuCu3vHvmu" +
                "2GGBbxFxPOJ437L1KaI=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>Gz6+F6fzwlL8DRLRS6slismvO7dHyRZmN+uaqY3dZndQIapdBubDf96VHD2z4p2H87qsRMn/m5Am" +
                "n2bSVmz6zFgPeIlzJrCeO7pwkSjdaclK21IR7rfbYR3i/YubNgbAJQbzW+QWysrkEq/5tPPyd5ni" +
                "EKihjZjxmOIZ2kgjmKq2FziAY4PEZHkTn2RgR4nGSWYgrgP+KxtMusTQ6QDPavx5YWduoyeqP8fZ" +
                "WWwbGyf/G9HZVmKzHeGzhdgctHhiNjudXzNru5aQpyceyQOQbt7fuInz1zdOv2lEa5iEfIQOtlPI" +
                "mrPE0rg+F476fpjU2FBNX0A63/D9MVg5rhj/rfw7qy/0No1B9nxLr2L+aH2HcU3rdI4rydaTkqcj" +
                "EuFrOrzWervUD7RtOzPjqBOnp73NvUgWaYXuuMEWLo4hpsihQA476TQhlsZVw/0PMrGzA1g5bJ9k" +
                "O2O7+v+gTSTeJ+ogIALIVnrBHsNshg2PA52p3X4i8orK+JPNYUSUX2uYiotjGFX9e74maE5T0Tf3" +
                "1uAQLgJsqv9OWUQWYJZ8HMUYsTbyohVao1Ei7CoJYjfuZQbd5m6QimEes4iN0Do0yDkuBERHAgt1" +
                "ckOsHT1hg4A75F6ufgQWzwoEviV4KqMfPzdp8apoheb42+vam0S2h86wpgvWWbtLZBHLWSHKNlyW" +
                "BhNS5TykasBXTZ9FpfJ3BjODLxWCFVCDFxkvswJ3wsqxSwbVokilf+MOQTugmh5bHfvxRtuTFvcn" +
                "6T39UNqx173JlyBuBSwBjTkVlMQio7Z4VG1XX2WiT1JJlrqL8da3NfZfWebLgYOM8I2pI6hp4BrJ" +
                "c5Fzp6glxbJX60qh5XMXbv7fL2nS/6/ZJ6FV2LYKEr41BYaEKr8xmUinUJRgF4qadZPM808eoDGN" +
                "cR62uwZ28vBz4Dgj7bKSfXMIa+DfH4ZL8IIPGTZxV/qQd87gPD0KEVN8Agl/bQrt3iUAun1fPM26" +
                "/zIOfSvAWzW1kEY2IMyVMIAapT7O0ByvUv6d</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></products>";


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
        Document document = loadEncryptionDocument();

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
        Key kek = CertificateUtils.generatePrivateKey(factory, CertificateUtils.CERTIFICATE_DIR + "certificate/testaio1.pem");
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

        outputDocToFile(document, "build/decryptedInfo.xml");
    }
}
