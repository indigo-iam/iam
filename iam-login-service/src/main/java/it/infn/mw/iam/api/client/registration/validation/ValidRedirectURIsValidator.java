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
package it.infn.mw.iam.api.client.registration.validation;

import static java.lang.String.format;

import java.util.Objects;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

@Component
@Scope("prototype")
public class ValidRedirectURIsValidator
    implements ConstraintValidator<ValidRedirectURIs, RegisteredClientDTO> {

  private final BlacklistedSiteService denyListService;

  public ValidRedirectURIsValidator(BlacklistedSiteService denyListService) {
    this.denyListService = denyListService;
  }

  @Override
  public boolean isValid(RegisteredClientDTO value, ConstraintValidatorContext context) {

    if (Objects.isNull(value.getRedirectUris())) {
      return true;
    }

    for (String uri : value.getRedirectUris()) {
      if (denyListService.isBlacklisted(uri)) {
        context.disableDefaultConstraintViolation();
        context
          .buildConstraintViolationWithTemplate(
              format("Invalid redirect URI: %s is not allowed", uri))
          .addConstraintViolation();
        return false;
      } else if (uri.contains("#")) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate("Invalid redirect URI: contains a fragment")
          .addConstraintViolation();
        return false;
      }
    }

    return true;

  }

}
