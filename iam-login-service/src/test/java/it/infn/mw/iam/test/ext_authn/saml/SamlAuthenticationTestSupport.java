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
package it.infn.mw.iam.test.ext_authn.saml;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.parser.SAMLObject;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;

import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.test.util.saml.SamlAssertionBuilder;
import it.infn.mw.iam.test.util.saml.SamlResponseBuilder;

public class SamlAuthenticationTestSupport {

  public static final String DEFAULT_IDP_ID = "https://idptestbed/idp/shibboleth";

  public static final String KEY_ALIAS = "iam-test";
  public static final String KS_PASSWORD = "iam-test";

  public static final String JIT1_NAMEID = "jit1";
  public static final String JIT1_EPPN = "jit1.eppn@idptestbed";
  public static final String JIT1_EPUID = "jit1.epuid@idptestbed";
  public static final String JIT1_GIVEN_NAME = "JustInTime1";
  public static final String JIT1_FAMILY_NAME = "Saml User";
  public static final String JIT1_MAIL = "jit1@example.org";

  public static final String T1_NAMEID = "1234";
  public static final String T1_EPPN = "test-user@idptestbed";
  public static final String T1_EPUID = "123456@idptestbed";
  public static final String T1_GIVEN_NAME = "Test";
  public static final String T1_SN = "Saml User";
  public static final String T1_MAIL = "test-user@example.org";

  public static final String T2_NAMEID = "4567";
  public static final String T2_EPPN = "test-user-2@idptestbed";
  public static final String T2_EPUID = "78901@idptestbed";
  public static final String T2_GIVEN_NAME = "Test";
  public static final String T2_SN = "Saml User 2";
  public static final String T2_MAIL = "test-user-2@example.org";

  public static final String EXT_AUTHN_URL = "/iam/authn-info";

  public static final IamSamlId T1_SAML_ID =
      new IamSamlId(DEFAULT_IDP_ID, Saml2Attribute.EPUID.getAttributeName(), T1_EPUID);
  

  @Autowired
  protected MetadataGenerator metadataGenerator;

  @Autowired
  protected ObjectMapper objectMapper;

  @Autowired
  protected MockMvc mvc;

  public String samlDefaultIdpLoginUrl() throws UnsupportedEncodingException {

    String defaultIdpUrl = String.format("/saml/login?idp=%s", DEFAULT_IDP_ID);

    return defaultIdpUrl;

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

  public SamlAssertionBuilder samlAssertionBuilder()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
    return new SamlAssertionBuilder(serviceCredential(), DEFAULT_IDP_ID);
  }

  public SamlResponseBuilder samlResponseBuilder()
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
    return new SamlResponseBuilder(serviceCredential(), DEFAULT_IDP_ID);
  }


  public Response buildNoAudienceInvalidResponse(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {
    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    // This is invalid since no AUDIENCE is set
    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T2_NAMEID)
      .eppn(T2_EPPN)
      .epuid(T2_EPUID)
      .givenName(T2_GIVEN_NAME)
      .sn(T2_SN)
      .mail(T2_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;

  }

  public Response buildNoAttributesInvalidResponse(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {
    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    // This is invalid since the assertion does not define
    // the minimum required attributes for the mapping
    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T2_NAMEID)
      .givenName(T2_GIVEN_NAME)
      .sn(T2_SN)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }

  public Response buildTest2Response(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {

    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T2_NAMEID)
      .eppn(T2_EPPN)
      .epuid(T2_EPUID)
      .givenName(T2_GIVEN_NAME)
      .sn(T2_SN)
      .mail(T2_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }

  public Response buildTest1Response(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {

    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T1_NAMEID)
      .eppn(T1_EPPN)
      .epuid(T1_EPUID)
      .givenName(T1_GIVEN_NAME)
      .sn(T1_SN)
      .mail(T1_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }


  public Response buildJitTest1Response(AuthnRequest authnRequest)
      throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
      SecurityException, SignatureException, MarshallingException {

    SamlAssertionBuilder sab = samlAssertionBuilder();

    DateTime issueTime = DateTime.now().minusSeconds(30);

    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(JIT1_NAMEID)
      .eppn(JIT1_EPPN)
      .epuid(JIT1_EPUID)
      .givenName(JIT1_GIVEN_NAME)
      .sn(JIT1_FAMILY_NAME)
      .mail(JIT1_MAIL)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .audience(metadataGenerator.getEntityId())
      .issueInstant(issueTime)
      .build();

    SamlResponseBuilder srb = samlResponseBuilder();
    Response r = srb.assertion(a)
      .recipient(authnRequest.getAssertionConsumerServiceURL())
      .requestId(authnRequest.getID())
      .issueInstant(DateTime.now())
      .build();

    return r;
  }

  @SuppressWarnings("rawtypes")
  public AuthnRequest getAuthnRequestFromSession(MockHttpSession session) {
    @SuppressWarnings("unchecked")
    Map<String, SAMLObject<?>> samlStorage =
        (Map<String, SAMLObject<?>>) session.getAttribute("_springSamlStorageKey");

    String authnRequestKey = samlStorage.keySet().iterator().next();

    return (AuthnRequest) ((SAMLObject) samlStorage.get(authnRequestKey)).getObject();
  }
}
