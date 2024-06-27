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
package it.infn.mw.iam.api.aup.model;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class AupRemindersValidator implements ConstraintValidator<AupReminders, String> {

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {

    if (value == null || value.isEmpty()) {
      context.buildConstraintViolationWithTemplate("");
      return false;
    }

    try {
      List<Integer> numbers = Arrays.stream(value.split(","))
        .map(String::trim)
        .map(Integer::parseInt)
        .collect(Collectors.toList());

      if (numbers.stream().anyMatch(i -> i <= 0)) {
        return false;
      }

      Set<Integer> uniqueNumbers = new HashSet<>(numbers);
      return uniqueNumbers.size() == numbers.size();
    } catch (NumberFormatException e) {
      return false;
    }
  }

}
