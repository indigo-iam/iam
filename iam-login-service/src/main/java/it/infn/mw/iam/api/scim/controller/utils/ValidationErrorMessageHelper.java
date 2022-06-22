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
package it.infn.mw.iam.api.scim.controller.utils;

import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

public class ValidationErrorMessageHelper {

  private ValidationErrorMessageHelper() {}

  public static String buildValidationErrorMessage(String errorMessage,
      BindingResult validationResult) {

    StringBuilder validationError = new StringBuilder();
    validationError.append(errorMessage + ": ");

    boolean first = true;

    for (ObjectError error : validationResult.getAllErrors()) {

      if (!first) {
        validationError.append(",");
      }

      if (error instanceof FieldError) {
        FieldError fieldError = (FieldError) error;

        validationError.append(String.format("[%s.%s : %s]", fieldError.getObjectName(),
            fieldError.getField(), fieldError.getDefaultMessage()));

      } else {

        validationError
            .append(String.format("[%s : %s]", error.getObjectName(), error.getDefaultMessage()));
      }

      first = false;
    }

    return validationError.toString();
  }

}
