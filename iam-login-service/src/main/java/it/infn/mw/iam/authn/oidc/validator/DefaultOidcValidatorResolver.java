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

import static java.util.Collections.emptyMap;
import static java.util.Objects.nonNull;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toMap;

import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.authn.common.ValidatorCheck;
import it.infn.mw.iam.authn.common.ValidatorResolver;
import it.infn.mw.iam.authn.common.config.ValidatorConfigError;
import it.infn.mw.iam.authn.common.config.ValidatorConfigParser;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;

@Service
public class DefaultOidcValidatorResolver implements ValidatorResolver<JWT> {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultOidcValidatorResolver.class);

  private final Map<String, ValidatorCheck<JWT>> checksByIssuer;

  @Autowired
  public DefaultOidcValidatorResolver(ValidatorConfigParser configParser,
      OidcProviderProperties properties) {
    Map<String, ValidatorCheck<JWT>> checks = emptyMap();

    try {
      checks = properties.getProviders()
        .stream()
        .filter(p -> nonNull(p.getValidator()))
        .collect(toMap(OidcProvider::getIssuer,
            p -> configParser.parseValidatorProperties(p.getValidator())));
    } catch (ValidatorConfigError e) {
      LOG.error("Error parsing oidc token validation rules: {}", e.getMessage(), e);
    } finally {
      checksByIssuer = checks;
    }
  }


  @Override
  public Optional<ValidatorCheck<JWT>> resolveChecks(String issuer) {
    return ofNullable(checksByIssuer.get(issuer));
  }

}
