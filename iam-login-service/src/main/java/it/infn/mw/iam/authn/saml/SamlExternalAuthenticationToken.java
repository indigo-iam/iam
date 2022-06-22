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
package it.infn.mw.iam.authn.saml;

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.SAML_TYPE;
import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.TYPE_ATTR;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPPN;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.GIVEN_NAME;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.MAIL;
import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.SN;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.opensaml.saml2.core.Attribute;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.collect.Maps;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSamlId;

public class SamlExternalAuthenticationToken
    extends AbstractExternalAuthenticationToken<ExpiringUsernameAuthenticationToken> {

  private static final long serialVersionUID = -7854473523011856692L;

  private final IamSamlId samlId;

  public SamlExternalAuthenticationToken(IamSamlId samlId,
      ExpiringUsernameAuthenticationToken authn, Date tokenExpiration, Object principal,
      Object credentials, Collection<? extends GrantedAuthority> authorities) {
    super(authn, tokenExpiration, principal, credentials, authorities);
    this.samlId = samlId;
  }

  @Override
  public Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor) {

    return visitor.buildInfoMap(this);
  }

  @Override
  public ExternalAuthenticationRegistrationInfo toExernalAuthenticationRegistrationInfo() {

    ExternalAuthenticationRegistrationInfo ri =
        new ExternalAuthenticationRegistrationInfo(ExternalAuthenticationType.SAML);

    SAMLCredential cred = (SAMLCredential) getExternalAuthentication().getCredentials();

    ri.setIssuer(samlId.getIdpId());
    ri.setSubject(samlId.getUserId());
    ri.setSubjectAttribute(samlId.getAttributeId());

    if (!isNullOrEmpty(cred.getAttributeAsString(GIVEN_NAME.getAttributeName()))) {
      ri.setGivenName(cred.getAttributeAsString(GIVEN_NAME.getAttributeName()));
    }

    if (!isNullOrEmpty(cred.getAttributeAsString(SN.getAttributeName()))) {
      ri.setFamilyName(cred.getAttributeAsString(SN.getAttributeName()));
    }

    if (!isNullOrEmpty(cred.getAttributeAsString(MAIL.getAttributeName()))) {
      ri.setEmail(cred.getAttributeAsString(MAIL.getAttributeName()));
    }

    if (!isNullOrEmpty(cred.getAttributeAsString(EPPN.getAttributeName()))) {
      ri.setSuggestedUsername(cred.getAttributeAsString(EPPN.getAttributeName()));
    }

    Map<String, String> additionalAttrs = Maps.newHashMap();
    additionalAttrs.putAll(buildAuthnInfoMap());

    ri.setAdditionalAttributes(additionalAttrs);

    return ri;
  }

  @Override
  public void linkToIamAccount(ExternalAccountLinker visitor, IamAccount account) {
    visitor.linkToIamAccount(account, this);
  }

  public IamSamlId getSamlId() {
    return samlId;
  }

  @Override
  public Map<String, String> buildAuthnInfoMap() {

    Map<String, String> authnInfo = new HashMap<>();

    authnInfo.put(TYPE_ATTR, SAML_TYPE);

    SAMLCredential cred = (SAMLCredential) getExternalAuthentication().getCredentials();

    authnInfo.put("idpEntityId", cred.getRemoteEntityID());

    for (Attribute attr : cred.getAttributes()) {

      Optional<Saml2Attribute> maybeKnownAttr = Saml2Attribute.byName(attr.getName());

      String attrName = attr.getName();

      if (maybeKnownAttr.isPresent()) {
        attrName = maybeKnownAttr.get().name();
      }

      String attrVal = cred.getAttributeAsString(attr.getName());

      if (!Objects.isNull(attrVal)) {
        authnInfo.put(attrName, attrVal);
      }
    }

    return authnInfo;
  }
}
