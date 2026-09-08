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
package it.infn.mw.iam.test.actuator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.config.ActuatorConfigResponse;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ActuatorUserProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.config.saml.IamSamlLoginShortcut;
import it.infn.mw.iam.config.saml.IamSamlProperties;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(ActuatorConfigEndpointTests.TestProvidersConfiguration.class)
class ActuatorConfigEndpointTests {

  @TestConfiguration
  static class TestProvidersConfiguration {

    @Bean
    @Primary
    OidcProviderProperties testOidcProviderProperties() {
      OidcClient client =
          new OidcClient(SECRET_VALUE, SECRET_VALUE, "openid profile", "S256", "RS256", null);

      OidcProvider provider = new OidcProvider();
      provider.setName("test-oidc-provider");
      provider.setIssuer("https://issuer.example");
      provider.setClient(client);
      provider.setEnabled(true);

      OidcProviderProperties properties = new OidcProviderProperties();

      properties.setProviders(List.of(provider));

      return properties;
    }

    @Bean
    @Primary
    IamSamlProperties testIamSamlProperties() {
      IamSamlLoginShortcut shortcut = new IamSamlLoginShortcut();

      shortcut.setName("test-saml-provider");
      shortcut.setEntityId("https://idp.example");
      shortcut.setEnabled(true);

      IamSamlProperties properties = new IamSamlProperties();

      properties.setLoginShortcuts(List.of(shortcut));

      return properties;
    }
  }

  private static final String SECRET_VALUE = "this-value-must-never-be-returned";

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private IamProperties iamProperties;

  @BeforeEach
  void setUpSensitiveIamProperties() {
    ActuatorUserProperties actuatorUser = new ActuatorUserProperties();
    actuatorUser.setUsername(SECRET_VALUE);
    actuatorUser.setPassword(SECRET_VALUE);
    iamProperties.setActuatorUser(actuatorUser);

    DashboardProperties dashboard = new DashboardProperties();
    dashboard.setEnabled(true);
    dashboard.setClientId(SECRET_VALUE);
    dashboard.setClientSecret(SECRET_VALUE);
    iamProperties.setDashboard(dashboard);
  }

  static Stream<String> ignoredIamPropertyPaths() {
    return Stream.of("/iamProperties/actuatorUser/username", "/iamProperties/actuatorUser/password",
        "/iamProperties/dashboard/clientId", "/iamProperties/dashboard/clientSecret");
  }

  @ParameterizedTest(name = "{0} must not be returned")
  @MethodSource("ignoredIamPropertyPaths")
  void shouldNotReturnIgnoredIamProperties(String jsonPointer) throws Exception {

    JsonNode response = getActuatorConfig();

    assertThat(response.at(jsonPointer).isMissingNode())
      .as("Expected JSON property %s to be absent", jsonPointer)
      .isTrue();
  }

  @Test
  void shouldNotLeakSensitiveIamPropertyValues() throws Exception {
    String response = performActuatorConfigRequest().getResponse().getContentAsString();

    assertThat(response).doesNotContain(SECRET_VALUE);
  }

  @Test
  void shouldReturnExpectedTopLevelProperties() throws Exception {
    JsonNode response = getActuatorConfig();

    assertThat(response.has("iamProperties")).isTrue();
    assertThat(response.has("oidcProviders")).isTrue();
    assertThat(response.has("samlProviders")).isTrue();

    assertThat(response.path("iamProperties").isObject()).isTrue();
    assertThat(response.path("oidcProviders").isArray()).isTrue();
    assertThat(response.path("samlProviders").isArray()).isTrue();
  }

  @Test
  void shouldNotReturnClientConfigurationForAnyOidcProvider() throws Exception {

    JsonNode providers = getActuatorConfig().path("oidcProviders");

    assertThat(providers.isArray()).isTrue();
    assertThat(providers).hasSize(1);

    JsonNode provider = providers.get(0);

    assertThat(provider.path("name").asText()).isEqualTo("test-oidc-provider");

    assertThat(provider.path("issuer").asText()).isEqualTo("https://issuer.example");

    assertThat(provider.has("client")).as("OIDC provider must not expose its client configuration")
      .isFalse();
  }

  @Test
  void shouldReturnSamlShortcutsWithoutUnexpectedFields() throws Exception {

    JsonNode providers = getActuatorConfig().path("samlProviders");

    assertThat(providers.isArray()).isTrue();
    assertThat(providers).hasSize(1);

    JsonNode provider = providers.get(0);

    assertThat(provider.path("name").asText()).isEqualTo("test-saml-provider");

    assertThat(provider.path("entityId").asText()).isEqualTo("https://idp.example");

    assertThat(provider.path("enabled").asBoolean()).isTrue();

    assertThat(fieldNames(provider)).containsOnly("name", "entityId", "loginButton", "enabled");
  }

  @Test
  void shouldApplyJsonIgnoreRulesWhenSerializingCompleteResponse() throws Exception {

    ActuatorUserProperties actuatorUser = new ActuatorUserProperties();
    actuatorUser.setUsername(SECRET_VALUE);
    actuatorUser.setPassword(SECRET_VALUE);

    DashboardProperties dashboard = new DashboardProperties();
    dashboard.setEnabled(true);
    dashboard.setClientId(SECRET_VALUE);
    dashboard.setClientSecret(SECRET_VALUE);

    IamProperties properties = new IamProperties();
    properties.setActuatorUser(actuatorUser);
    properties.setDashboard(dashboard);

    OidcProvider oidcProvider = new OidcProvider();
    oidcProvider.setName("test-oidc-provider");
    oidcProvider.setIssuer("https://issuer.example");
    OidcClient oidcClient =
        new OidcClient(SECRET_VALUE, SECRET_VALUE, "openid profile", "S256", "RS256", null);

    oidcProvider.setClient(oidcClient);

    IamSamlLoginShortcut samlProvider = new IamSamlLoginShortcut();

    samlProvider.setName("test-saml-provider");
    samlProvider.setEntityId("https://idp.example");
    samlProvider.setEnabled(true);

    ActuatorConfigResponse response =
        new ActuatorConfigResponse(properties, List.of(oidcProvider), List.of(samlProvider));

    JsonNode json = objectMapper.valueToTree(response);

    assertThat(json.at("/iamProperties/actuatorUser/username").isMissingNode()).isTrue();

    assertThat(json.at("/iamProperties/actuatorUser/password").isMissingNode()).isTrue();

    assertThat(json.at("/iamProperties/dashboard/clientId").isMissingNode()).isTrue();

    assertThat(json.at("/iamProperties/dashboard/clientSecret").isMissingNode()).isTrue();

    JsonNode serializedOidcProvider = json.path("oidcProviders").get(0);

    assertThat(serializedOidcProvider.path("name").asText()).isEqualTo("test-oidc-provider");

    assertThat(serializedOidcProvider.path("issuer").asText()).isEqualTo("https://issuer.example");

    assertThat(serializedOidcProvider.has("client"))
      .as("The @JsonIgnore OIDC client must be absent")
      .isFalse();

    JsonNode serializedSamlProvider = json.path("samlProviders").get(0);

    assertThat(serializedSamlProvider.path("name").asText()).isEqualTo("test-saml-provider");

    assertThat(serializedSamlProvider.path("entityId").asText()).isEqualTo("https://idp.example");

    assertThat(serializedSamlProvider.path("enabled").asBoolean()).isTrue();

    assertThat(fieldNames(serializedSamlProvider)).containsOnly("name", "entityId", "loginButton",
        "enabled");

    assertThat(json.toString()).doesNotContain(SECRET_VALUE);
  }

  @Test
  void shouldNotReturnOidcClientConfiguration() throws Exception {
    JsonNode providers = getActuatorConfig().path("oidcProviders");

    assertThat(providers.isArray()).isTrue();
    assertThat(providers.size()).isEqualTo(1);

    JsonNode provider = providers.get(0);

    assertThat(provider.path("name").asText()).isEqualTo("test-oidc-provider");
    assertThat(provider.path("issuer").asText()).isEqualTo("https://issuer.example");
    assertThat(provider.has("client")).isFalse();
  }

  @Test
  void shouldReturnSamlShortcuts() throws Exception {
    JsonNode providers = getActuatorConfig().path("samlProviders");

    assertThat(providers.isArray()).isTrue();
    assertThat(providers.size()).isEqualTo(1);

    JsonNode provider = providers.get(0);

    assertThat(provider.path("name").asText()).isEqualTo("test-saml-provider");
    assertThat(provider.path("entityId").asText()).isEqualTo("https://idp.example");
    assertThat(provider.path("enabled").asBoolean()).isTrue();
  }

  private JsonNode getActuatorConfig() throws Exception {
    MvcResult result = performActuatorConfigRequest();

    return objectMapper.readTree(result.getResponse().getContentAsString());
  }

  private MvcResult performActuatorConfigRequest() throws Exception {
    return mockMvc.perform(get("/actuator/config")).andExpect(status().isOk()).andReturn();
  }

  private static List<String> fieldNames(JsonNode node) {
    List<String> result = new ArrayList<>();
    node.fieldNames().forEachRemaining(result::add);
    return result;
  }
}
