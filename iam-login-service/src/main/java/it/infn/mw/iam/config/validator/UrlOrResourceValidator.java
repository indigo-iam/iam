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
package it.infn.mw.iam.config.validator;

import java.net.MalformedURLException;
import java.net.URL;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

public class UrlOrResourceValidator
    implements ConstraintValidator<UrlOrResource, String> {

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {

    if (value == null) {
      return true;
    }
    try {
      new URL(value);
      return true;
    } catch (MalformedURLException e) {
      if (getClass().getResourceAsStream(value) != null) {
        return true;
      }
      HibernateConstraintValidatorContext hibernateContext = context.unwrap(
          HibernateConstraintValidatorContext.class );
      hibernateContext.disableDefaultConstraintViolation();
      hibernateContext.addMessageParameter("message", e.getMessage())
        .buildConstraintViolationWithTemplate("Invalid URL: {message}")
        .addConstraintViolation();
      return false;
    }
    
  }

}
