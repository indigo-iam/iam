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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.config.login.LoginButtonImage;

@RunWith(MockitoJUnitRunner.class)
public class LoginButtonImageValidatorTests {

  private static ValidatorFactory validatorFactory;
  private static Validator validator;

  @BeforeClass
  public static void createValidator() {
      validatorFactory = Validation.buildDefaultValidatorFactory();
      validator = validatorFactory.getValidator();
  }

  @AfterClass
  public static void close() {
      validatorFactory.close();
  }

  @Test
  public void nullImageUrl() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl(null);
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertTrue(violations.isEmpty());
  }

  @Test
  public void validUrl() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("https://example.org/test.png");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertTrue(violations.isEmpty());
  }

  @Test
  public void invalidUrl() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("abcd://example.org/test.png");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertFalse(violations.isEmpty());
    assertThat(violations.stream().findFirst().get().getMessage(), is("Invalid URL: unknown protocol: abcd"));
  }

  @Test
  public void validResourcePath() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("/resources/images/edugain-logo.gif");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertTrue(violations.isEmpty());
  }

  @Test
  public void invalidResourcePath() {
    LoginButtonImage image = new LoginButtonImage();
    image.setUrl("/resources/not/found");
    Set<ConstraintViolation<LoginButtonImage>> violations =  validator.validate(image);
    assertFalse(violations.isEmpty());
    assertThat(violations.stream().findFirst().get().getMessage(), is("Invalid URL: no protocol: /resources/not/found"));
  }
}
