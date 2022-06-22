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
package it.infn.mw.iam.test.util.saml;

import static org.opensaml.common.xml.SAMLConstants.SAML20_NS;

import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.common.collect.Lists;

public class SamlUtils {

  public static void prettyPrintSamlObject(XMLObject object) throws MarshallingException {

    MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    Marshaller m = marshallerFactory.getMarshaller(object);

    System.out.println(XMLHelper.prettyPrintXML(m.marshall(object)));
  }

  public static String signAndSerializeToBase64(Response response) throws Throwable {
    String responseString = signAndSerializeToString(response);
    return Base64.encodeBytes(responseString.getBytes());
  }

  public static String signAndSerializeToString(Response response) throws MarshallingException,
      SignatureException, XPathExpressionException, ParserConfigurationException {

    MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();

    // Signature computation fails without this
    document.setStrictErrorChecking(false);

    Element marshalledResponse =
	marshallerFactory.getMarshaller(response).marshall(response, document);

    // Signature computation fails without this, due to
    // https://bugs.openjdk.java.net/browse/JDK-8017171
    marshalledResponse.setIdAttribute("ID", true);

    List<Signature> signatures = Lists.newArrayList();

    NodeList assertionElements = marshalledResponse.getElementsByTagNameNS(SAML20_NS, "Assertion");

    // Signature computation fails without this, due to
    // https://bugs.openjdk.java.net/browse/JDK-8017171
    for (int i = 0; i < assertionElements.getLength(); i++) {
      Element a = (Element) assertionElements.item(0);
      a.setIdAttribute("ID", true);
    }

    response.getAssertions().forEach(a -> signatures.add(a.getSignature()));
    signatures.add(response.getSignature());

    Signer.signObjects(signatures);

    return XMLHelper.nodeToString(marshalledResponse);
  }

  public static String getAttributeValue(Assertion assertion, String attributeId) {
    List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();
    for (Attribute a : attributes) {
      if (a.getName().equals(attributeId)) {
	XSString stringValue = (XSString) a.getAttributeValues().get(0);
	return stringValue.toString();
      }
    }

    return null;
  }

  public static void validateSignature(Response response, Credential cred)
      throws ValidationException {

    if (response.getSignature() == null) {
      return;
    }

    SignatureValidator sv = new SignatureValidator(cred);
    sv.validate(response.getSignature());

    for (Assertion a : response.getAssertions()) {
      if (a.getSignature() != null) {
	sv.validate(a.getSignature());
      }
    }
  }
}
