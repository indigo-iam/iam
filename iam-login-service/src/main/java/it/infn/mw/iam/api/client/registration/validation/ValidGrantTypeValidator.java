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

import static java.util.Objects.isNull;

import java.util.HashSet;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

public class ValidGrantTypeValidator
    implements ConstraintValidator<ValidGrantType, RegisteredClientDTO> {

  @Override
  public boolean isValid(RegisteredClientDTO value, ConstraintValidatorContext context) {

    if (isNull(value.getGrantTypes())) {
      value.setGrantTypes(new HashSet<>());
      value.getGrantTypes().add(AuthorizationGrantType.CODE);
    }

    if ((value.getGrantTypes().contains(AuthorizationGrantType.CODE)
        || value.getGrantTypes().contains(AuthorizationGrantType.IMPLICIT))
        && (isNull(value.getRedirectUris()) || value.getRedirectUris().isEmpty())) {
      context.disableDefaultConstraintViolation();
      context
        .buildConstraintViolationWithTemplate("Authorization code requires a valid redirect uri")
        .addConstraintViolation();
      return false;
    }

    return true;
  }

}
