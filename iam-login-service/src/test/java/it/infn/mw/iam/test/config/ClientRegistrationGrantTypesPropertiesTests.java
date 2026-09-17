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

import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.DEVICE_CODE;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.PASSWORD;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.TOKEN_EXCHANGE;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.GrantTypes.DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.GrantTypes.DEFAULT_FORBIDDEN_FOR_USER_CLIENTS;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ByteArrayResource;

import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.GrantTypes;

@ExtendWith(OutputCaptureExtension.class)
class ClientRegistrationGrantTypesPropertiesTests {

  private static final String USER_PROPERTY =
      "client-registration.grant-types.forbidden-for-user-clients";
  private static final String ANONYMOUS_PROPERTY =
      "client-registration.grant-types.forbidden-for-anonymous-clients";

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner().withUserConfiguration(TestConfig.class);

  @Configuration(proxyBeanMethods = false)
  @EnableConfigurationProperties(ClientRegistrationProperties.class)
  static class TestConfig {
  }

  private ApplicationContextRunner withYaml(String yaml) {
    return contextRunner.withInitializer(context -> {
      try {
        context.getEnvironment()
          .getPropertySources()
          .addFirst(new YamlPropertySourceLoader()
            .load("test", new ByteArrayResource(yaml.getBytes(StandardCharsets.UTF_8)))
            .get(0));
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
    });
  }

  private static GrantTypes grantTypes(ApplicationContext context) {
    return context.getBean(ClientRegistrationProperties.class).getGrantTypes();
  }

  @Test
  void missingConfigurationKeepsDefaults(CapturedOutput output) {

    contextRunner.run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(grantTypes(context).forbiddenForUserClients())
        .isEqualTo(DEFAULT_FORBIDDEN_FOR_USER_CLIENTS);
      assertThat(grantTypes(context).forbiddenForAnonymousClients())
        .isEqualTo(DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS);
    });

    assertThat(output).doesNotContain("client-registration.grant-types");
  }

  @Test
  void missingListKeepsItsDefault() {

    contextRunner.withPropertyValues(USER_PROPERTY + "=PASSWORD,TOKEN_EXCHANGE,DEVICE_CODE")
      .run(context -> {
        assertThat(context).hasNotFailed();
        assertThat(grantTypes(context).forbiddenForUserClients())
          .containsExactlyInAnyOrder(PASSWORD, TOKEN_EXCHANGE, DEVICE_CODE);
        assertThat(grantTypes(context).forbiddenForAnonymousClients())
          .isEqualTo(DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS);
      });
  }

  @Test
  void yamlListsAreBound(CapturedOutput output) {

    withYaml("""
        client-registration:
          grant-types:
            forbidden-for-user-clients:
              - TOKEN_EXCHANGE
              - PASSWORD
            forbidden-for-anonymous-clients:
              - CLIENT_CREDENTIALS
              - TOKEN_EXCHANGE
              - PASSWORD
              - DEVICE_CODE
        """).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(grantTypes(context).forbiddenForUserClients()).containsExactlyInAnyOrder(PASSWORD,
          TOKEN_EXCHANGE);
      assertThat(grantTypes(context).forbiddenForAnonymousClients())
        .containsExactlyInAnyOrder(CLIENT_CREDENTIALS, TOKEN_EXCHANGE, PASSWORD, DEVICE_CODE);
    });

    assertThat(output).doesNotContain("client-registration.grant-types");
  }

  @Test
  void unknownGrantTypeFailsStartup() {

    contextRunner.withPropertyValues(USER_PROPERTY + "=PASSWORD,NOT_A_GRANT_TYPE").run(context -> {
      assertThat(context).hasFailed();
      assertThat(context.getStartupFailure()).hasStackTraceContaining("NOT_A_GRANT_TYPE");
    });
  }

  @Test
  void explicitEmptyYamlListRemovesRestrictions(CapturedOutput output) {

    withYaml("""
        client-registration:
          grant-types:
            forbidden-for-user-clients: []
        """).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(grantTypes(context).forbiddenForUserClients()).isEmpty();
      assertThat(grantTypes(context).forbiddenForAnonymousClients())
        .isEqualTo(DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS);
    });

    assertThat(output).contains(USER_PROPERTY)
      .contains(PASSWORD.name())
      .contains(TOKEN_EXCHANGE.name())
      .doesNotContain(ANONYMOUS_PROPERTY);
  }

  @Test
  void explicitEmptyValueRemovesRestrictions(CapturedOutput output) {

    contextRunner.withPropertyValues(ANONYMOUS_PROPERTY + "=").run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(grantTypes(context).forbiddenForAnonymousClients()).isEmpty();
      assertThat(grantTypes(context).forbiddenForUserClients())
        .isEqualTo(DEFAULT_FORBIDDEN_FOR_USER_CLIENTS);
    });

    assertThat(output).contains(ANONYMOUS_PROPERTY).doesNotContain(USER_PROPERTY);
  }

  @Test
  void weakerThanDefaultRestrictionsAreLogged(CapturedOutput output) {

    contextRunner.withPropertyValues(ANONYMOUS_PROPERTY + "=PASSWORD,TOKEN_EXCHANGE")
      .run(context -> {
        assertThat(context).hasNotFailed();
        assertThat(grantTypes(context).forbiddenForAnonymousClients())
          .containsExactlyInAnyOrder(PASSWORD, TOKEN_EXCHANGE);
      });

    assertThat(output).contains(ANONYMOUS_PROPERTY)
      .contains(CLIENT_CREDENTIALS.name())
      .doesNotContain(USER_PROPERTY);
  }

}
