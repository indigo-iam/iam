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

public class AupRemindersAndSignatureValidator
    implements ConstraintValidator<AupRemindersAndSignature, AupDTO> {

  @Override
  public boolean isValid(AupDTO value, ConstraintValidatorContext context) {

    Long signatureValidityInDays = value.getSignatureValidityInDays();
    String aupRemindersInDays = value.getAupRemindersInDays();

    if (signatureValidityInDays == null) {
      context.disableDefaultConstraintViolation();
      context
        .buildConstraintViolationWithTemplate("Invalid AUP: signatureValidityInDays is required")
        .addPropertyNode("signatureValidityInDays")
        .addConstraintViolation();
      return false;
    }

    if (signatureValidityInDays < 0) {
      context.disableDefaultConstraintViolation();
      context
        .buildConstraintViolationWithTemplate("Invalid AUP: signatureValidityInDays must be >= 0")
        .addPropertyNode("signatureValidityInDays")
        .addConstraintViolation();
      return false;
    }

    if (signatureValidityInDays == 0) {
      if (aupRemindersInDays != null && !aupRemindersInDays.isEmpty()) {
        context.disableDefaultConstraintViolation();
        context
          .buildConstraintViolationWithTemplate(
              "Invalid AUP: aupRemindersInDays cannot be set if signatureValidityInDays is 0")
          .addConstraintViolation();
        return false;
      }
      return true;
    }

    if (aupRemindersInDays != null) {
      try {
        List<Integer> numbers = Arrays.stream(aupRemindersInDays.split(","))
          .map(String::trim)
          .map(Integer::parseInt)
          .collect(Collectors.toList());

        if (numbers.stream().anyMatch(i -> i <= 0)) {
          context.disableDefaultConstraintViolation();
          context
            .buildConstraintViolationWithTemplate(
                "Invalid AUP: zero or negative values for reminders are not allowed")
            .addConstraintViolation();
          return false;
        }

        if (numbers.stream().anyMatch(i -> i >= signatureValidityInDays)) {
          context.disableDefaultConstraintViolation();
          context
            .buildConstraintViolationWithTemplate(
                "Invalid AUP: aupRemindersInDays must be smaller than signatureValidityInDays")
            .addConstraintViolation();
          return false;
        }

        Set<Integer> uniqueNumbers = new HashSet<>(numbers);
        if (uniqueNumbers.size() != numbers.size()) {
          context.disableDefaultConstraintViolation();
          context
            .buildConstraintViolationWithTemplate(
                "Invalid AUP: duplicate values for reminders are not allowed")
            .addConstraintViolation();
          return false;
        }

        return true;
      } catch (NumberFormatException e) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate("Invalid AUP: non-integer value found for aupRemindersInDays")
          .addConstraintViolation();
        return false;
      }
    }
    return true;
  }

}
