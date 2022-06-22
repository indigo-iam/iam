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
package it.infn.mw.iam.test.saml;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.springframework.security.saml.key.JKSKeyManager;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.google.common.collect.ImmutableMap;

import it.infn.mw.iam.test.util.saml.SamlAssertionBuilder;
import it.infn.mw.iam.test.util.saml.SamlResponseBuilder;
import it.infn.mw.iam.test.util.saml.SamlUtils;



public class AssertionBuilderTests {

  public static final String KEY_ALIAS = "iam-test";
  public static final String KS_PASSWORD = "iam-test";


  @BeforeClass
  public static void setup() throws ConfigurationException {

    DefaultBootstrap.bootstrap();
  }


  @Test
  public void testBuildAssertion() throws Throwable {

    Credential serviceCredential = serviceCredential();

    SamlAssertionBuilder ab = new SamlAssertionBuilder(serviceCredential, "test");

    DateTime now = DateTime.now();
    DateTime expiration = now.plusHours(1);

    Assertion createAssertion = ab.subject("sub")
      .issueInstant(now)
      .expirationTime(expiration)
      .nameId("43948")
      .recipient("recipient")
      .requestId("32342")
      .eppn("sub@test")
      .epuid("321231323@test")
      .givenName("Illo")
      .sn("Camughe")
      .mail("sub@mail.test")
      .eptid()
      .build();


    SamlResponseBuilder rb = new SamlResponseBuilder(serviceCredential, "test");
    Response createdResponse = rb.assertion(createAssertion)
      .recipient("recipient")
      .requestId("32342")
      .issueInstant(now)
      .build();

    String responseString = SamlUtils.signAndSerializeToString(createdResponse);

    Response r = unmarshallResponse(responseString);

    SamlUtils.validateSignature(r, verifyCredential());

    // Response checks

    assertThat(r.getIssueInstant().getMillis(), equalTo(now.getMillis()));
    assertThat(r.getInResponseTo(), equalTo("32342"));
    assertThat(r.getDestination(), equalTo("recipient"));

    assertThat(r.getAssertions(), not(empty()));

    Assertion a = r.getAssertions().get(0);

    assertThat(a.getSubject().getNameID().getValue(), equalTo("43948"));
    assertThat(a.getSubject().getNameID().getFormat(), equalTo(NameID.PERSISTENT));

    assertThat(a.getConditions().getNotBefore().getMillis(), equalTo(now.getMillis()));
    assertThat(a.getConditions().getNotOnOrAfter().getMillis(), equalTo(expiration.getMillis()));

    assertThat(a.getAttributeStatements(), not(empty()));

  }

  protected Response unmarshallResponse(String responseString) throws Throwable {
    return unmarshallResponse(parseXmlFromString(responseString));
  }

  protected Response unmarshallResponse(Document doc) throws UnmarshallingException {
    UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(doc.getDocumentElement());

    return (Response) unmarshaller.unmarshall(doc.getDocumentElement());
  }

  protected Document parseXmlFromString(String xmlString)
      throws ParserConfigurationException, UnsupportedEncodingException, SAXException, IOException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);

    DocumentBuilder db = factory.newDocumentBuilder();
    return db.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));


  }

  public Credential verifyCredential()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
    Credential serviceCredential = serviceCredential();
    BasicCredential bc = new BasicCredential();
    bc.setPublicKey(serviceCredential.getPublicKey());
    bc.setUsageType(UsageType.SIGNING);
    return bc;
  }

  public Credential serviceCredential()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {

    KeyStore ks = testKeyStore();
    JKSKeyManager keyManager =
	new JKSKeyManager(ks, ImmutableMap.of(KEY_ALIAS, KS_PASSWORD), KEY_ALIAS);

    return keyManager.getDefaultCredential();
  }

  public KeyStore testKeyStore()
      throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

    KeyStore ks = KeyStore.getInstance("JKS");

    ks.load(this.getClass().getResourceAsStream("/saml/idp-signing.jks"), "iam-test".toCharArray());
    return ks;

  }

}
