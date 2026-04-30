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
import org.springframework.core.io.ResourceLoader;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.util.JwkKeyStoreLoader;

@SpringBootTest(classes = {IamLoginService.class})
public class JwkKeyStoreStartupTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner().withUserConfiguration(TestConfig.class)
        .withPropertyValues("spring.profiles.active=prod");

  @Test
  void shouldFailWhenKeystoreLocationMissingInProd() {
    contextRunner.run(context -> {
      assertThat(context).hasFailed();

      assertThat(context.getStartupFailure())
        .hasMessageContaining("JWK keystore location must be configured");
    });
  }

  @Configuration
  static class TestConfig {

    @Bean
    JwkKeyStoreLoader jwkKeyStoreLoader(ResourceLoader resourceLoader) {
      return new JwkKeyStoreLoader(resourceLoader);
    }

    @Bean
    IamProperties iamProperties() {
      return new IamProperties();
    }

    @Bean(name = "defaultKeyStore")
    JwkKeyStore defaultKeyStore(JwkKeyStoreLoader loader, IamProperties iamProperties) {
      String location = iamProperties.getJwk().getKeystoreLocation();

      if (location == null || location.isBlank()) {
        throw new IllegalStateException("JWK keystore location must be configured");
      }

      return loader.load(location);
    }
  }
}
