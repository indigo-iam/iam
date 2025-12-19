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
package it.infn.mw.voms.properties;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import it.infn.mw.voms.properties.VomsProperties.VOMSAAProperties;

class VomsPropertiesValidatorTests {

  static ValidatorFactory validatorFactory;
  static Validator validator;
  static final List<String> invalidExampleVONames = List.of("VO-name.test", "vo_name.test",
      "1vo-name.test", "_vo-name.test", "vo_name.test", "vo_name.test1");
  static final String validVoName = "vo1-name.test";
  static final String validVoHost = "vo-host";

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
  void invalidVoName() {
    VOMSAAProperties vomsaa = new VOMSAAProperties();
    vomsaa.setHost(validVoHost);
    for (String voName : invalidExampleVONames) {
      vomsaa.setVoName(voName);
      Set<ConstraintViolation<VOMSAAProperties>> violations = validator.validate(vomsaa);
      assertFalse(violations.isEmpty());
    }
  }

  @Test
  void validVoName() {
    VOMSAAProperties vomsaa = new VOMSAAProperties();
    vomsaa.setHost(validVoHost);
    vomsaa.setVoName(validVoName);
    Set<ConstraintViolation<VOMSAAProperties>> violations = validator.validate(vomsaa);
    assertTrue(violations.isEmpty());
  }
}
