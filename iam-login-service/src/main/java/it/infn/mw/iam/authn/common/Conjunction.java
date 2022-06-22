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

import static it.infn.mw.iam.authn.common.ValidatorResult.success;

import java.util.List;

public class Conjunction<T> extends CompositeValidatorCheck<T> {

  public Conjunction(List<ValidatorCheck<T>> checks, String message) {
    super(checks, message);
  }

  @Override
  public ValidatorResult validate(T credential) {
    for (ValidatorCheck<T> c : getChecks()) {

      ValidatorResult result = c.validate(credential);
      if (!result.isSuccess()) {
        return handleFailure(result);
      }

    }
    return success();
  }

}
