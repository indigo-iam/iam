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
package it.infn.mw.iam.authn.common;

import static it.infn.mw.iam.authn.common.ValidatorResult.failure;
import static it.infn.mw.iam.authn.common.ValidatorResult.success;

import java.util.List;

public class Negation<T> extends CompositeValidatorCheck<T> {

  public Negation(List<ValidatorCheck<T>> checks, String message) {
    super(checks, message);
  }

  @Override
  public ValidatorResult validate(T credential) {

    // Negation applies only to the first check
    ValidatorCheck<T> first = getChecks().get(0);
    ValidatorResult result = first.validate(credential);

    if (result.isFailure()) {
      return success();
    } else if (result.isSuccess()) {
      return failure(getMessage());
    }

    return result;
  }

}
