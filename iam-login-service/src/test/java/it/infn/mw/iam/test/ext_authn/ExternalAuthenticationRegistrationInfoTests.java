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
package it.infn.mw.iam.test.ext_authn;


import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;
import it.infn.mw.iam.test.ext_authn.saml.SamlTestConfig;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.saml.SamlAssertionBuilder;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, SamlTestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
public class ExternalAuthenticationRegistrationInfoTests extends SamlAuthenticationTestSupport {

  public static final String ENTITY_ID = "https://assertion-consumer.example";
  public static final String ASSERTION_CONSUMER_URL = "https://assertion-consumer.example/saml";


  @Test
  public void testOidcMinimalInfoConversion() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);

    when(token.getSub()).thenReturn("test-oidc-subject");
    when(token.getIssuer()).thenReturn("test-oidc-issuer");

    OidcExternalAuthenticationToken extAuthToken =
        new OidcExternalAuthenticationToken(token, "test-oidc-subject", null);

    ExternalAuthenticationRegistrationInfo uri =
        extAuthToken.toExernalAuthenticationRegistrationInfo();

    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.OIDC));
    assertThat(uri.getGivenName(), Matchers.nullValue());
    assertThat(uri.getFamilyName(), Matchers.nullValue());
    assertThat(uri.getEmail(), Matchers.nullValue());
    assertThat(uri.getSubject(), equalTo("test-oidc-subject"));
    assertThat(uri.getIssuer(), equalTo("test-oidc-issuer"));

  }

  @Test
  public void testOidcEmailAndNameReturnedIfPresent() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);

    UserInfo userinfo = mock(UserInfo.class);

    when(userinfo.getEmail()).thenReturn("test@test.org");

    when(userinfo.getGivenName()).thenReturn("Test Given Name");
    when(userinfo.getFamilyName()).thenReturn("Test Family Name");

    when(token.getSub()).thenReturn("test-oidc-subject");
    when(token.getIssuer()).thenReturn("test-oidc-issuer");
    when(token.getUserInfo()).thenReturn(userinfo);

    OidcExternalAuthenticationToken extAuthToken =
        new OidcExternalAuthenticationToken(token, "test-oidc-subject", null);

    ExternalAuthenticationRegistrationInfo uri =
        extAuthToken.toExernalAuthenticationRegistrationInfo();

    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.OIDC));
    assertThat(uri.getSubject(), equalTo("test-oidc-subject"));
    assertThat(uri.getIssuer(), equalTo("test-oidc-issuer"));
    assertThat(uri.getGivenName(), equalTo("Test Given Name"));
    assertThat(uri.getFamilyName(), equalTo("Test Family Name"));
    assertThat(uri.getEmail(), equalTo("test@test.org"));



  }

  @Test
  public void testSamlMinimalInfoConversion() {
    ExpiringUsernameAuthenticationToken token = mock(ExpiringUsernameAuthenticationToken.class);
    SAMLCredential cred = mock(SAMLCredential.class);

    when(token.getCredentials()).thenReturn(cred);
    when(token.getName()).thenReturn("test-saml-subject");
    when(cred.getRemoteEntityID()).thenReturn("test-saml-issuer");

    IamSamlId samlId = new IamSamlId("test-saml-issuer", Saml2Attribute.EPUID.getAttributeName(),
        "test-saml-subject");

    SamlExternalAuthenticationToken extAuthToken =
        new SamlExternalAuthenticationToken(samlId, token, token.getTokenExpiration(),
            "test-saml-subject", token.getCredentials(), token.getAuthorities());

    ExternalAuthenticationRegistrationInfo uri =
        extAuthToken.toExernalAuthenticationRegistrationInfo();
    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.SAML));
    assertThat(uri.getSubject(), equalTo("test-saml-subject"));
    assertThat(uri.getIssuer(), equalTo("test-saml-issuer"));
    assertThat(uri.getSubjectAttribute(), equalTo(samlId.getAttributeId()));
    assertThat(uri.getGivenName(), Matchers.nullValue());
    assertThat(uri.getFamilyName(), Matchers.nullValue());
    assertThat(uri.getEmail(), Matchers.nullValue());

  }

  @Test
  public void testSamlEmailAndNameReturnedIfPresent() {
    ExpiringUsernameAuthenticationToken token = mock(ExpiringUsernameAuthenticationToken.class);

    SAMLCredential cred = mock(SAMLCredential.class);
    when(cred.getRemoteEntityID()).thenReturn("test-saml-issuer");

    when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn("Test Given Name");
    when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName()))
      .thenReturn("Test Family Name");
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn("test@test.org");

    when(token.getCredentials()).thenReturn(cred);
    when(token.getName()).thenReturn("test-saml-subject");

    IamSamlId samlId = new IamSamlId("test-saml-issuer", Saml2Attribute.EPUID.getAttributeName(),
        "test-saml-subject");

    SamlExternalAuthenticationToken extAuthToken =
        new SamlExternalAuthenticationToken(samlId, token, token.getTokenExpiration(),
            "test-saml-subject", token.getCredentials(), token.getAuthorities());

    ExternalAuthenticationRegistrationInfo uri =
        extAuthToken.toExernalAuthenticationRegistrationInfo();
    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.SAML));
    assertThat(uri.getSubject(), equalTo("test-saml-subject"));
    assertThat(uri.getIssuer(), equalTo("test-saml-issuer"));
    assertThat(uri.getSubjectAttribute(), equalTo(samlId.getAttributeId()));
    assertThat(uri.getGivenName(), equalTo("Test Given Name"));
    assertThat(uri.getFamilyName(), equalTo("Test Family Name"));
    assertThat(uri.getEmail(), equalTo("test@test.org"));

  }


  @Test
  public void testSamlAdditionalAttributes() throws NoSuchAlgorithmException, CertificateException,
      KeyStoreException, IOException, SecurityException, SignatureException, MarshallingException {
    ExpiringUsernameAuthenticationToken token = mock(ExpiringUsernameAuthenticationToken.class);


    SamlAssertionBuilder sab = samlAssertionBuilder();

    Assertion a = sab.issuer(DEFAULT_IDP_ID)
      .nameId(T1_NAMEID)
      .eppn(T1_EPPN)
      .epuid(T1_EPUID)
      .singleStringValuedAttribute("urn:oid:1.2.3.4.5", "12345")
      .givenName(T1_GIVEN_NAME)
      .sn(T1_SN)
      .mail(T1_MAIL)
      .recipient(ASSERTION_CONSUMER_URL)
      .requestId("01")
      .audience(metadataGenerator.getEntityId())
      .build();


    List<Attribute> attributes = Lists.newArrayList();

    for (AttributeStatement s : a.getAttributeStatements()) {
      attributes.addAll(s.getAttributes());
    }

    SAMLCredential cred = new SAMLCredential(a.getSubject().getNameID(), a, DEFAULT_IDP_ID,
        attributes, metadataGenerator.getEntityId());

    when(token.getCredentials()).thenReturn(cred);
    when(token.getName()).thenReturn(T1_EPUID);

    IamSamlId samlId =
        new IamSamlId(DEFAULT_IDP_ID, Saml2Attribute.EPUID.getAttributeName(), T1_EPUID);

    SamlExternalAuthenticationToken extAuthToken =
        new SamlExternalAuthenticationToken(samlId, token, token.getTokenExpiration(), T1_EPUID,
            token.getCredentials(), token.getAuthorities());

    ExternalAuthenticationRegistrationInfo uri =
        extAuthToken.toExernalAuthenticationRegistrationInfo();
    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.SAML));
    assertThat(uri.getSubject(), equalTo(T1_EPUID));
    assertThat(uri.getEmail(), equalTo(T1_MAIL));
    assertThat(uri.getAdditionalAttributes().get("urn:oid:1.2.3.4.5"), equalTo("12345"));


  }

}
