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
package it.infn.mw.iam.authn.saml.util;

import static java.lang.String.format;

import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.persistence.model.IamSamlId;

public class AttributeUserIdentifierResolver extends AbstractSamlUserIdentifierResolver {

  Saml2Attribute attribute;

  public AttributeUserIdentifierResolver(Saml2Attribute attribute) {
    super(attribute.name());
    this.attribute = attribute;
  }

  @Override
  public SamlUserIdentifierResolutionResult resolveSamlUserIdentifier(
      SAMLCredential samlCredential) {

    String attributeValue = samlCredential.getAttributeAsString(attribute.getAttributeName());

    if (attributeValue == null) {
      return SamlUserIdentifierResolutionResult
        .resolutionFailure(format("Attribute '%s:%s' not found in assertion", attribute.getAlias(),
            attribute.getAttributeName()));
    }

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(samlCredential.getRemoteEntityID());
    samlId.setAttributeId(attribute.getAttributeName());
    samlId.setUserId(attributeValue);

    return SamlUserIdentifierResolutionResult.resolutionSuccess(samlId);

  }
}
