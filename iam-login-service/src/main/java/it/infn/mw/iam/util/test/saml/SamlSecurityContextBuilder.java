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
package it.infn.mw.iam.util.test.saml;

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.CERN_FIRST_NAME;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.CERN_PERSON_ID;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.GIVEN_NAME;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.MAIL;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.SN;
import static org.mockito.Mockito.when;

import org.mockito.Mockito;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.util.test.SecurityContextBuilderSupport;

public class SamlSecurityContextBuilder extends SecurityContextBuilderSupport {

  public static final String DEFAULT_IDP_ID = "https://idptestbed/idp/shibboleth";
  SAMLCredential samlCredential;

  String subjectAttribute = SamlAttributeNames.eduPersonUniqueId;

  public SamlSecurityContextBuilder() {
    samlCredential = Mockito.mock(SAMLCredential.class);
    issuer = DEFAULT_IDP_ID;
    subject = "test-saml-user";
  }

  public SamlSecurityContextBuilder notNullOrEmptySamlAttribute(Saml2Attribute attribute,
      String attributeValue) {
    if (!isNullOrEmpty(attributeValue)) {
      samlAttribute(attribute, attributeValue);
    }
    return this;
  }

  public SamlSecurityContextBuilder samlAttribute(Saml2Attribute attribute, String attributeValue) {
    when(samlCredential.getAttributeAsString(attribute.getAttributeName()))
      .thenReturn(attributeValue);
    return this;
  }

  public SamlSecurityContextBuilder subjectAttribute(String subjectAttr) {
    this.subjectAttribute = subjectAttr;
    return this;
  }

  @Override
  public SecurityContextBuilderSupport email(String email) {
    when(samlCredential.getAttributeAsString(MAIL.getAttributeName())).thenReturn(email);
    return this;
  }

  @Override
  public SecurityContextBuilderSupport name(String givenName, String familyName) {

    if (!Strings.isNullOrEmpty(givenName) && Strings.isNullOrEmpty(familyName)) {
      when(samlCredential.getAttributeAsString(GIVEN_NAME.getAttributeName()))
        .thenReturn(givenName);
      when(samlCredential.getAttributeAsString(SN.getAttributeName())).thenReturn(familyName);
    }

    return this;
  }

  public SamlSecurityContextBuilder cernPersonId(String cernPersonId) {
    return notNullOrEmptySamlAttribute(CERN_PERSON_ID, cernPersonId);
  }

  public SamlSecurityContextBuilder cernFirstName(String name) {
    return notNullOrEmptySamlAttribute(CERN_FIRST_NAME, name);
  }

  public SamlSecurityContextBuilder cernLastName(String lastName) {
    return notNullOrEmptySamlAttribute(Saml2Attribute.CERN_LAST_NAME, lastName);
  }

  public SamlSecurityContextBuilder cernEmail(String email) {
    return notNullOrEmptySamlAttribute(Saml2Attribute.CERN_EMAIL, email);
  }

  public SamlSecurityContextBuilder cernHomeInstitute(String institute) {
    return notNullOrEmptySamlAttribute(Saml2Attribute.CERN_HOME_INSTITUTE, institute);
  }

  @Override
  public SecurityContext buildSecurityContext() {
    SecurityContext context = SecurityContextHolder.createEmptyContext();

    when(samlCredential.getRemoteEntityID()).thenReturn(issuer);

    when(samlCredential.getAttributeAsString(subjectAttribute)).thenReturn(subject);

    ExpiringUsernameAuthenticationToken samlToken = new ExpiringUsernameAuthenticationToken(
        expirationTime, subject, samlCredential, authorities);

    IamSamlId samlId = new IamSamlId(issuer, subjectAttribute, subject);

    SamlExternalAuthenticationToken token = new SamlExternalAuthenticationToken(samlId, samlToken,
        samlToken.getTokenExpiration(), subject, samlToken.getCredentials(), authorities);

    context.setAuthentication(token);

    return context;

  }

}
