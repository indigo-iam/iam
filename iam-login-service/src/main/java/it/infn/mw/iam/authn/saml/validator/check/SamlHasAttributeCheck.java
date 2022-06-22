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
package it.infn.mw.iam.authn.saml.validator.check;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.authn.common.ValidatorResult.failure;
import static it.infn.mw.iam.authn.common.ValidatorResult.success;
import static java.lang.String.format;
import static java.util.Objects.isNull;

import org.opensaml.saml2.core.Attribute;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.common.BaseValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResult;

public class SamlHasAttributeCheck extends BaseValidatorCheck<SAMLCredential> {

  private final String attributeName;

  private SamlHasAttributeCheck(String attributeOid, String message) {
    super(message);
    this.attributeName = attributeOid;
  }

  @Override
  public ValidatorResult validate(SAMLCredential credential) {
    Attribute attribute = credential.getAttribute(attributeName);
    if (isNull(attribute)) {
      return handleFailure(failure(format("Attribute '%s' not found", attributeName)));
    }
    return success();
  }

  public static ValidatorCheck<SAMLCredential> hasAttribute(String attributeName, String message) {
    checkArgument(!isNullOrEmpty(attributeName), "attributeName must be non-null and not empty");
    return new SamlHasAttributeCheck(attributeName, message);
  }
  
  public static ValidatorCheck<SAMLCredential> hasAttribute(String attributeName) {
    return hasAttribute(attributeName, null);
  }

}
