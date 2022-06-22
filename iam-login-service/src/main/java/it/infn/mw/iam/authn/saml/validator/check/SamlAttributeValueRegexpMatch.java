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
import static java.lang.String.format;
import static java.util.Objects.isNull;
import static java.util.regex.Pattern.compile;

import java.util.regex.Pattern;

import org.opensaml.saml2.core.Attribute;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.common.BaseValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResult;

public class SamlAttributeValueRegexpMatch extends BaseValidatorCheck<SAMLCredential> {

  private final String attributeName;
  private final String regexp;
  private final Pattern pattern;


  private SamlAttributeValueRegexpMatch(String attributeName, String regexp, String message) {
    super(message);
    this.attributeName = attributeName;
    this.regexp = regexp;
    this.pattern = compile(regexp);
  }

  @Override
  public ValidatorResult validate(SAMLCredential credential) {
    Attribute attr = credential.getAttribute(attributeName);

    if (isNull(attr)) {
      return handleFailure(failure(format("Attribute '%s' not found", attributeName)));
    }

    String[] values = credential.getAttributeAsStringArray(attributeName);

    for (String v : values) {
      if (pattern.matcher(v).matches()) {
        return ValidatorResult.success();
      }
    }

    return handleFailure(failure(
        format("No attribute '%s' value found matching regexp: '%s'", attributeName, regexp)));

  }

  public static ValidatorCheck<SAMLCredential> attrValueMatches(String attributeName,
      String regexp) {
    return attrValueMatches(attributeName, regexp, null);
  }
  
  public static ValidatorCheck<SAMLCredential> attrValueMatches(String attributeName,
      String regexp, String message) {
    checkArgument(!isNullOrEmpty(attributeName), "attributeName must not be null or empty");
    checkArgument(!isNullOrEmpty(regexp), "regexp must not be null or empty");
    return new SamlAttributeValueRegexpMatch(attributeName, regexp, message);
  }


}
