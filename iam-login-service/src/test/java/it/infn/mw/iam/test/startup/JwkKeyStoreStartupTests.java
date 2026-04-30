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
package it.infn.mw.iam.test.startup;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.JWKProperties;
import it.infn.mw.iam.config.JWTCriptoConfig;

@SpringBootTest(classes = {IamLoginService.class})
public class JwkKeyStoreStartupTests {

  static final String DEFAULT_KEYSTORE_LOCATION = "classpath:keystore.jwks";

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner().withUserConfiguration(JWTCriptoConfig.class, TestConfig.class)
        .withPropertyValues("spring.profiles.active=prod");

  @Test
  void shouldFailWhenKeystoreLocationMissingInProd() {
    contextRunner.run(context -> {
      assertThat(context).hasFailed();

      assertThat(context.getStartupFailure())
        .hasMessageContaining("Error loading JWK keystore from " + DEFAULT_KEYSTORE_LOCATION);
    });
  }

  @Configuration
  static class TestConfig {

    @Bean
    IamProperties iamProperties() {
      JWKProperties jwk = new JWKProperties();
      jwk.setKeystoreLocation(DEFAULT_KEYSTORE_LOCATION);
      IamProperties props = new IamProperties();
      props.setJwk(jwk);
      return props;
    }
  }
}
