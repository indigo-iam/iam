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
package it.infn.mw.iam.test.config;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.config.login.LoginButtonImage;

@ExtendWith(MockitoExtension.class)
class LoginButtonImageValidatorTests {

  private static ValidatorFactory validatorFactory;
  private static Validator validator;

  @BeforeAll
  static void createValidator() {
      validatorFactory = Validation.buildDefaultValidatorFactory();
      validator = validatorFactory.getValidator();
  }

  @AfterAll
  static void close() {
      validatorFactory.close();
  }

  @Test
  void nullImageUrl() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl(null);
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertTrue(violations.isEmpty());
  }

  @Test
  void validUrl() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("https://example.org/test.png");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertTrue(violations.isEmpty());
  }

  @Test
  void invalidUrl() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("abcd://example.org/test.png");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertFalse(violations.isEmpty());
    assertThat(violations.stream().findFirst().get().getMessage(), is("Invalid URL: unknown protocol: abcd"));
  }

  @Test
  void validResourcePath() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("/resources/images/edugain-logo.gif");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertTrue(violations.isEmpty());
  }

  @Test
  void invalidResourcePath() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("/resources/not/found");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertFalse(violations.isEmpty());
    assertThat(violations.stream().findFirst().get().getMessage(), is("Invalid URL: no protocol: /resources/not/found"));
  }
}
