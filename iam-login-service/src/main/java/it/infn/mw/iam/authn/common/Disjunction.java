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

import static it.infn.mw.iam.authn.common.ValidatorResult.error;
import static it.infn.mw.iam.authn.common.ValidatorResult.failure;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class Disjunction<T> extends CompositeValidatorCheck<T> {

  public Disjunction(List<ValidatorCheck<T>> checks, String message) {
    super(checks, message);
  }

  @Override
  public ValidatorResult validate(T credential) {

    List<String> messages = new ArrayList<>();

    boolean hadErrors = false;

    for (ValidatorCheck<T> c : getChecks()) {

      ValidatorResult result = c.validate(credential);

      if (result.isSuccess()) {
        return result;
      } else {
        hadErrors = result.isError() || hadErrors;
        messages.add(result.getMessage());
      }
    }

    final String errorMsg = joinSkippingNulls(messages);
    return handleFailure(hadErrors ? error(errorMsg) : failure(errorMsg));
  }

  static String joinSkippingNulls(Iterable<?> items) {
    return StreamSupport.stream(items.spliterator(), false)
      .filter(Objects::nonNull)
      .map(String::valueOf)
      .collect(Collectors.joining(","));
  }
}
