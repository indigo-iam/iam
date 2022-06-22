/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.KeyStoreX509CredentialAdapter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SamlDecryptUtil {

  public Response parse(String samlXml)
      throws IOException, SAXException, ParserConfigurationException {
    Response response;
    Element root;
    StringReader reader = new StringReader(samlXml);
    InputSource is = new InputSource(reader);

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setNamespaceAware(true);
    DocumentBuilder documentBuilder = null;
    documentBuilder = factory.newDocumentBuilder();

    Document doc = documentBuilder.parse(is);
    root = doc.getDocumentElement();
    response = unmarshall(root);

    return response;
  }

  @SuppressWarnings("unchecked")
  public <T> T unmarshall(Element element) {
    try {
      UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
      return (T) unmarshallerFactory.getUnmarshaller(element).unmarshall(element);
    } catch (UnmarshallingException ux) {
      throw new RuntimeException(ux);
    }
  }

  public Element marshall(XMLObject xmlObject) throws MarshallingException {

    Element element;

    MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
    Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
    element = marshaller.marshall(xmlObject);

    return element;
  }

  public void print(XMLObject xmlObject) {

    try {

      Element element = marshall(xmlObject);

      TransformerFactory trfactory = TransformerFactory.newInstance();
      trfactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      trfactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
      Transformer tr = trfactory.newTransformer();
      tr.setOutputProperty(OutputKeys.INDENT, "yes");
      tr.setOutputProperty(OutputKeys.METHOD, "xml");
      tr.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", String.valueOf(4));
      tr.transform(new DOMSource(element), new StreamResult(System.out));

    } catch (Exception t) {

      printExceptionAndExit(t);

    }

  }

  private void printExceptionAndExit(Throwable t) {

    t.printStackTrace();
    System.exit(1);

  }

  void initializeOpenSAML() {

    try {

      DefaultBootstrap.bootstrap();

    } catch (ConfigurationException e) {

      printExceptionAndExit(e);
    }
  }

  private Assertion decryptEncryptedAssertion(Credential credential,
      EncryptedAssertion encryptedAssertion) throws Exception {
    StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
    Decrypter decrypter = new Decrypter(null, resolver, new InlineEncryptedKeyResolver());
    decrypter.setRootInNewDocument(true);
    return decrypter.decrypt(encryptedAssertion);
  }

  public SamlDecryptUtil() throws Exception {
    initializeOpenSAML();

    String xmlResponsePath = System.getenv("SAML_RESPONSE_PATH");
    String ksPath = System.getenv("KS_PATH");
    String ksAlias = System.getenv("KS_ALIAS");
    String ksPassword = System.getenv("KS_PASSWORD");

    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(new FileInputStream(ksPath), ksPassword.toCharArray());

    KeyStoreX509CredentialAdapter credential =
        new KeyStoreX509CredentialAdapter(ks, ksAlias, ksPassword.toCharArray());

    String xmlDoc = new String(Files.readAllBytes(Paths.get(xmlResponsePath)));
    Response response = parse(xmlDoc);

    Assertion assertion =
        decryptEncryptedAssertion(credential, response.getEncryptedAssertions().get(0));

    print(assertion);
  }

  public static void main(String[] args) throws Exception {
    new SamlDecryptUtil();
  }
}
