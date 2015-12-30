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

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.globallogic.xmlsec.utils.CertificateUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;

/**
 * This sample demonstrates how to encrypt data inside an xml document.
 *
 * @author Vishal Mahajan (Sun Microsystems)
 */
public class Encrypter {

    static {
        org.apache.xml.security.Init.init();
    }

    private static Document stringToXML(String xmlString) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document document = null;
        try {
            document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xmlString)));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return document;
    }

    private static SecretKey generateSymmetricKey() throws Exception {
        String jceAlgorithmName = "AES";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static String xmlToString(Document doc) throws Exception {

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc.getDocumentElement()), new StreamResult(writer));
        String result = writer.toString();
        System.out.println(result);
        return result;
    }

    public static void main(String unused[]) throws Exception {
        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><products><product id=\"1144\"  xmlns=\"http://example.com/product-info\"  xmlns:html=\"http://www.w3.org/1999/xhtml\"><name xml:lang=\"en\">Python Perfect IDE</name><description>Uses mind-reading technology to anticipate and accommodate all user needs in Python development. Implements all <html:code>from __future__ import</html:code>features though the year 3000. Works well with<code>1166</code>.</description></product><p:product id=\"1166\" xmlns:p=\"http://example.com/product-info\"><p:name>XSLT Perfect IDE</p:name><p:description xmlns:html=\"http://www.w3.org/1999/xhtml\" xmlns:xl=\"http://www.w3.org/1999/xlink\"> <p:code>red</p:code><html:code>blue</html:code><html:div> <ref xl:type=\"simple\" xl:href=\"index.xml\">A link</ref></html:div></p:description></p:product></products>";
        Document document = stringToXML(xmlString);
        /*
         * Get a key to be used for encrypting the element.
         * Here we are generating an AES key.
         */
        Key symmetricKey = generateSymmetricKey();
        /*
         * Get a key to be used for encrypting the symmetric key.
         */

        Key kek = CertificateUtils.extractPublicKey("testaio2.pem");
        String algorithmURI = XMLCipher.RSA_v1dot5;
        XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
        keyCipher.init(XMLCipher.WRAP_MODE, kek);
        EncryptedKey encryptedKey = keyCipher.encryptKey(document, symmetricKey);

        /*
         * Let us encrypt the contents of the document element.
         */
        Element rootElement = document.getDocumentElement();

        algorithmURI = XMLCipher.AES_128;

        XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

        /*
         * Setting keyinfo inside the encrypted data being prepared.
         */
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        /*
         * doFinal -
         * "true" below indicates that we want to encrypt element's content
         * and not the element itself. Also, the doFinal method would
         * modify the document by replacing the EncrypteData element
         * for the data to be encrypted.
         */
        xmlCipher.doFinal(document, rootElement, true);
        xmlToString(document);
    }
}
