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
package it.infn.mw.iam.authn.saml.validator;

import static java.util.stream.Collectors.toMap;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResolver;
import it.infn.mw.iam.authn.common.config.ValidatorConfigParser;
import it.infn.mw.iam.config.saml.IamSamlProperties;
import it.infn.mw.iam.config.saml.IamSamlProperties.IssuerValidationProperties;

@Service
public class DefaultSamlValidatorResolver implements ValidatorResolver<SAMLCredential> {

  private final ValidatorCheck<SAMLCredential> defaultValidator;
  private final Map<String, ValidatorCheck<SAMLCredential>> validators;


  @Autowired
  public DefaultSamlValidatorResolver(ValidatorConfigParser parser, IamSamlProperties props) {

    if (!Objects.isNull(props.getDefaultValidator())) {
      defaultValidator = parser.parseValidatorProperties(props.getDefaultValidator());
    } else {
      defaultValidator = null;
    }

    validators = props.getValidators()
      .stream()
      .collect(toMap(IssuerValidationProperties::getEntityId,
          p -> parser.parseValidatorProperties(p.getValidator())));
  }

  @Override
  public Optional<ValidatorCheck<SAMLCredential>> resolveChecks(String issuer) {
    return Optional.ofNullable(validators.getOrDefault(issuer, defaultValidator));
  }

}
