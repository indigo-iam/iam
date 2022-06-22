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
package it.infn.mw.iam.authn.oidc.validator;

import java.util.Optional;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorError;
import it.infn.mw.iam.authn.common.ValidatorResolver;
import it.infn.mw.iam.authn.common.ValidatorResult;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;

@Service
public class DefaultOidcTokenValidator
    implements AuthenticationValidator<OIDCAuthenticationToken> {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultOidcTokenValidator.class);

  private final ValidatorResolver<JWT> resolver;

  @Autowired
  public DefaultOidcTokenValidator(ValidatorResolver<JWT> validatorResolver) {
    resolver = validatorResolver;
  }


  @Override
  public void validateAuthentication(OIDCAuthenticationToken token) {

    Optional<ValidatorCheck<JWT>> checks = resolver.resolveChecks(token.getIssuer());

    if (!checks.isPresent()) {
      LOG.debug("No checks defined for issuer: {}", token.getIssuer());
    } else {
      ValidatorResult result = checks.get().validate(token.getIdToken());
      LOG.debug("{} validation result: {} {}", token.getIdToken(), result.getStatus(),
          result.getMessage());
      if (!result.isSuccess()) {
        throw new ValidatorError(result.getMessage());
      }
    }
  }

}
