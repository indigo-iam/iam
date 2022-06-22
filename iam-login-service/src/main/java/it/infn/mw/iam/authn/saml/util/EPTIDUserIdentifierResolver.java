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

import static it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult.resolutionFailure;
import static java.lang.String.format;
import static java.util.Objects.isNull;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.base.Strings;

import it.infn.mw.iam.persistence.model.IamSamlId;

public class EPTIDUserIdentifierResolver extends AttributeUserIdentifierResolver {

  public EPTIDUserIdentifierResolver() {
    super(Saml2Attribute.EPTID);
  }

  @Override
  public SamlUserIdentifierResolutionResult resolveSamlUserIdentifier(
      SAMLCredential samlCredential) {

    if (Strings.isNullOrEmpty(samlCredential.getRemoteEntityID())) {
      return SamlUserIdentifierResolutionResult
          .resolutionFailure(format("Malformed assertion while looking for attribute '%s:%s': remoteEntityID null or empty", attribute.getAlias(),
              attribute.getAttributeName()));
    }
    
    Attribute eptidAttr = samlCredential.getAttribute(attribute.getAttributeName());

    if (eptidAttr == null) {
      return SamlUserIdentifierResolutionResult
        .resolutionFailure(format("Attribute '%s:%s' not found in assertion", attribute.getAlias(),
            attribute.getAttributeName()));
    }

    if (isNull(eptidAttr.getAttributeValues())) {
      return SamlUserIdentifierResolutionResult
        .resolutionFailure(format("Attribute '%s:%s' is malformed: null or empty list of values",
            attribute.getAlias(), attribute.getAttributeName()));
    }

    if (eptidAttr.getAttributeValues().isEmpty()) {
      return SamlUserIdentifierResolutionResult
        .resolutionFailure(format("Attribute '%s:%s' is malformed: null or empty list of values",
            attribute.getAlias(), attribute.getAttributeName()));
    }

    if (eptidAttr.getAttributeValues().size() > 1) {
      return SamlUserIdentifierResolutionResult
        .resolutionFailure(format("Attribute '%s:%s' is malformed: more than one value found",
            attribute.getAlias(), attribute.getAttributeName()));
    }


    XMLObject maybeAttributeValue = eptidAttr.getAttributeValues().get(0);

    if (!(maybeAttributeValue instanceof XSAny)) {
      return SamlUserIdentifierResolutionResult.resolutionFailure(
          format("Attribute '%s:%s' is malformed: attribute value is not an XSAny",
              attribute.getAlias(), attribute.getAttributeName()));
    }

    if (!maybeAttributeValue.hasChildren()) {
      return SamlUserIdentifierResolutionResult.resolutionFailure(
          format("Attribute '%s:%s' is malformed: attribute value has no children elements",
              attribute.getAlias(), attribute.getAttributeName()));
    }

    XMLObject maybeNameId = maybeAttributeValue.getOrderedChildren().get(0);

    if (!(maybeNameId instanceof NameID)) {
      return SamlUserIdentifierResolutionResult.resolutionFailure(format(
          "Attribute '%s:%s' is malformed: attribute value first children value is not a NameID",
          attribute.getAlias(), attribute.getAttributeName()));
    }

    NameID nameId = (NameID) maybeNameId;
    
    if (!isNull(nameId.getFormat()) && !nameId.getFormat().equals(NameIDType.PERSISTENT)) {
      return resolutionFailure(
          format("Attribute '%s:%s' is malformed: resolved NameID is not persistent: %s",
              attribute.getAlias(), attribute.getAttributeName(), nameId.getFormat()));
    }

    IamSamlId samlId = new IamSamlId();
    
    samlId.setIdpId(samlCredential.getRemoteEntityID());
    samlId.setAttributeId(attribute.getAttributeName());
    samlId.setUserId(nameId.getValue());

    return SamlUserIdentifierResolutionResult.resolutionSuccess(samlId);
  }
}
