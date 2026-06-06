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

import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.mockito.Mockito;
import org.opensaml.saml2.core.Attribute;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.util.test.SecurityContextBuilderSupport;

public class SamlSecurityContextBuilder extends SecurityContextBuilderSupport {

  public static final String DEFAULT_IDP_ID = "https://idptestbed/idp/shibboleth";

  private final SAMLCredential samlCredential;

  private final Map<String, String> attributes = new HashMap<>();

  String subjectAttribute = SamlAttributeNames.eduPersonUniqueId;

  public SamlSecurityContextBuilder() {
    this.samlCredential = Mockito.mock(SAMLCredential.class);
    this.issuer = DEFAULT_IDP_ID;
    this.subject = "test-saml-user";
  }

  public SamlSecurityContextBuilder samlAttribute(Saml2Attribute attr, String value) {
    if (value != null) {
      return samlAttributeByName(attr.getAttributeName(), value);
    }
    return this;
  }

  public SamlSecurityContextBuilder samlAttributeByName(String name, String value) {
    if (value != null) {
      attributes.put(name, value);
      when(samlCredential.getAttributeAsString(name)).thenReturn(value);
    }
    return this;
  }

  @Override
  public SecurityContextBuilderSupport email(String email) {
    samlAttribute(Saml2Attribute.MAIL, email);
    return this;
  }

  @Override
  public SecurityContextBuilderSupport name(String givenName, String familyName) {
    samlAttribute(Saml2Attribute.GIVEN_NAME, givenName);
    samlAttribute(Saml2Attribute.SN, familyName);
    return this;
  }

  @Override
  public SecurityContextBuilderSupport username(String username) {
    samlAttribute(Saml2Attribute.EPPN, username);
    return this;
  }

  public SamlSecurityContextBuilder cernPersonId(String cernPersonId) {
    return samlAttribute(Saml2Attribute.CERN_PERSON_ID, cernPersonId);
  }

  public SamlSecurityContextBuilder cernFirstName(String name) {
    return samlAttribute(Saml2Attribute.CERN_FIRST_NAME, name);
  }

  public SamlSecurityContextBuilder cernLastName(String lastName) {
    return samlAttribute(Saml2Attribute.CERN_LAST_NAME, lastName);
  }

  public SamlSecurityContextBuilder cernEmail(String email) {
    return samlAttribute(Saml2Attribute.CERN_EMAIL, email);
  }

  public SamlSecurityContextBuilder cernHomeInstitute(String institute) {
    return samlAttribute(Saml2Attribute.CERN_HOME_INSTITUTE, institute);
  }

  @Override
  public SecurityContext buildSecurityContext() {

    SecurityContext context = SecurityContextHolder.createEmptyContext();

    when(samlCredential.getRemoteEntityID()).thenReturn(issuer);

    when(samlCredential.getAttributes()).thenAnswer(inv -> {
      return attributes.keySet().stream().map(name -> {
        Attribute a = Mockito.mock(Attribute.class);
        when(a.getName()).thenReturn(name);
        return a;
      }).toList();
    });

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
