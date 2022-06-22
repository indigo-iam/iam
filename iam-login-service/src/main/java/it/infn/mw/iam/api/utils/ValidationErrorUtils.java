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
package it.infn.mw.iam.api.utils;

import java.util.stream.Collectors;

import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;

public class ValidationErrorUtils {
  
  private ValidationErrorUtils() {
    // prevent instantiation
  }

  public static void handleValidationError(String prefix, BindingResult result) {

    if (result.hasErrors()) {
      throw new IllegalArgumentException(
          String.format("%s: [%s]", prefix, stringifyValidationError(result)));
    }
  }
  
  public static String stringifyValidationError(BindingResult result) {
    StringBuilder sb = new StringBuilder();
    if (result.hasGlobalErrors()) {
      sb.append(result.getGlobalErrors().get(0).getDefaultMessage());
    } else {
      sb.append(result.getFieldErrors().stream().map(FieldError::getDefaultMessage).collect(Collectors.joining(",")));
    }
    return sb.toString();
  }
}
