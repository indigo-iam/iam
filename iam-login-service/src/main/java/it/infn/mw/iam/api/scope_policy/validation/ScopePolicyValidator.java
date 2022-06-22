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
package it.infn.mw.iam.api.scope_policy.validation;

import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.PATH;
import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.REGEXP;
import static java.util.Objects.isNull;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import it.infn.mw.iam.api.scope_policy.ScopePolicyDTO;

public class ScopePolicyValidator implements ConstraintValidator<ScopePolicy, ScopePolicyDTO> {

  private static final String INVALID_SCOPE_LENGTH_MSG =
      "{it.infn.mw.iam.api.scope_policy.validation.ScopePolicyValidator.invalidScopeLength.message}";

  private static final String NULL_SCOPE_MSG =
      "{it.infn.mw.iam.api.scope_policy.validation.ScopePolicyValidator.nullScope.message}";

  private static final String EMPTY_SCOPE_MSG =
      "{it.infn.mw.iam.api.scope_policy.validation.ScopePolicyValidator.emptyScope.message}";

  private static final String NULL_MATCHING_POLICY_MSG =
      "{it.infn.mw.iam.api.scope_policy.validation.ScopePolicyValidator.nullMatchingPolicy.message}";

  private static final int SCOPE_MIN_LENGTH = 1;
  private static final int SCOPE_MAX_LENGTH = 255;

  public ScopePolicyValidator() {
    // empty
  }

  @Override
  public void initialize(ScopePolicy constraintAnnotation) {
    // empty
  }

  private boolean isValidMatchingPolicy(ScopePolicyDTO value, ConstraintValidatorContext context) {

    if (isNull(value.getMatchingPolicy())) {
      context.disableDefaultConstraintViolation();
      context.buildConstraintViolationWithTemplate(NULL_MATCHING_POLICY_MSG)
        .addConstraintViolation();
      return false;
    }

    if ((value.getMatchingPolicy().equals(PATH.name())
        || value.getMatchingPolicy().equals(REGEXP.name()))
        && (isNull(value.getScopes()) || value.getScopes().isEmpty())) {

      context.disableDefaultConstraintViolation();
      context.buildConstraintViolationWithTemplate(EMPTY_SCOPE_MSG).addConstraintViolation();
      return false;
    }

    return true;
  }


  private boolean hasValidScopes(ScopePolicyDTO value, ConstraintValidatorContext context) {

    if (isNull(value.getScopes()) || value.getScopes().isEmpty()) {
      return true;
    }

    for (String s : value.getScopes()) {
      if (isNull(s)) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(NULL_SCOPE_MSG).addConstraintViolation();
        return false;
      }

      final int scopeLength = s.length();
      if (scopeLength < SCOPE_MIN_LENGTH || scopeLength > SCOPE_MAX_LENGTH) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(INVALID_SCOPE_LENGTH_MSG)
          .addConstraintViolation();
        return false;
      }
    }

    return true;
  }

  @Override
  public boolean isValid(ScopePolicyDTO value, ConstraintValidatorContext context) {
    boolean nullChecks =
        !(value == null || (value.getAccount() != null && value.getGroup() != null));
    return nullChecks && isValidMatchingPolicy(value, context) && hasValidScopes(value, context);
  }

}
