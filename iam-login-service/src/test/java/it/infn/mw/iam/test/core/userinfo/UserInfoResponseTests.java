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
package it.infn.mw.iam.test.core.userinfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.SUB;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.userinfo.UserInfoResponse;

class UserInfoResponseTests {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void constructorRequiresSubClaim() {

    Map<String, Object> claims = Map.of();

    assertThatThrownBy(() -> new UserInfoResponse(claims)).isInstanceOf(NullPointerException.class)
      .hasMessage("Missing sub key in UserInfoResponse claims");
  }

  @Test
  void constructorRejectsNullSubClaim() {

    Map<String, Object> claims = new HashMap<>();
    claims.put(SUB, null);

    assertThatThrownBy(() -> new UserInfoResponse(claims)).isInstanceOf(NullPointerException.class)
      .hasMessage("Missing sub key in UserInfoResponse claims");
  }

  @Test
  void constructorConvertsSubToString() {

    UserInfoResponse response = new UserInfoResponse(Map.of(SUB, 12345));

    assertThat(response.getSub()).isEqualTo("12345");
  }

  @Test
  void constructorPopulatesAdditionalFields() {

    Map<String, Object> claims = Map.of(SUB, "12345", "given_name", "John", "family_name", "Doe",
        "email", "john@example.org", "preferred_username", "jdoe");

    UserInfoResponse response = new UserInfoResponse(claims);

    assertThat(response.getSub()).isEqualTo("12345");
    assertThat(response.getAdditionalFields()).containsEntry("given_name", "John")
      .containsEntry("family_name", "Doe")
      .containsEntry("email", "john@example.org")
      .containsEntry("preferred_username", "jdoe")
      .doesNotContainKey(SUB);
  }

  @Test
  void convenienceGettersReturnClaimValues() {

    Map<String, Object> claims = Map.of(SUB, "12345", "given_name", "John", "family_name", "Doe",
        "email", "john@example.org", "preferred_username", "jdoe");

    UserInfoResponse response = new UserInfoResponse(claims);

    assertThat(response.getGivenName()).isEqualTo("John");
    assertThat(response.getFamilyName()).isEqualTo("Doe");
    assertThat(response.getEmail()).isEqualTo("john@example.org");
    assertThat(response.getPreferredUsername()).isEqualTo("jdoe");
  }

  @Test
  void convenienceGettersConvertValuesToString() {

    Map<String, Object> claims = Map.of(SUB, "12345", "given_name", 42, "email", true);

    UserInfoResponse response = new UserInfoResponse(claims);

    assertThat(response.getGivenName()).isEqualTo("42");
    assertThat(response.getEmail()).isEqualTo("true");
  }

  @Test
  void convenienceGettersReturnNullWhenClaimsAreMissing() {

    UserInfoResponse response = new UserInfoResponse(Map.of(SUB, "12345"));

    assertThat(response.getGivenName()).isNull();
    assertThat(response.getFamilyName()).isNull();
    assertThat(response.getEmail()).isNull();
    assertThat(response.getPreferredUsername()).isNull();
  }

  @Test
  void getNameReturnsFormattedName() {

    Map<String, Object> claims =
        Map.of(SUB, "12345", "given_name", "John", "middle_name", "William", "family_name", "Doe");

    UserInfoResponse response = new UserInfoResponse(claims);

    assertThat(response.getName()).isEqualTo("John William Doe");
  }

  @Test
  void addAdditionalFieldStoresNonSubClaims() {

    UserInfoResponse response = new UserInfoResponse(Map.of(SUB, "12345"));

    response.addAdditionalField("custom_claim", "custom-value");

    assertThat(response.getAdditionalFields()).containsEntry("custom_claim", "custom-value");
  }

  @Test
  void addAdditionalFieldIgnoresSubCaseInsensitively() {

    UserInfoResponse response = new UserInfoResponse(Map.of(SUB, "original"));

    response.addAdditionalField("sub", "replacement");
    response.addAdditionalField("SUB", "replacement");
    response.addAdditionalField("SuB", "replacement");

    assertThat(response.getSub()).isEqualTo("original");
    assertThat(response.getAdditionalFields()).doesNotContainKeys("sub", "SUB", "SuB");
  }

  @Test
  void serializationFlattensAdditionalFields() throws Exception {

    UserInfoResponse response = new UserInfoResponse(
        Map.of(SUB, "12345", "given_name", "John", "email", "john@example.org"));

    JsonNode json = objectMapper.readTree(objectMapper.writeValueAsString(response));

    assertThat(json.get("sub").asText()).isEqualTo("12345");
    assertThat(json.get("given_name").asText()).isEqualTo("John");
    assertThat(json.get("email").asText()).isEqualTo("john@example.org");
    assertThat(json.has("additionalFields")).isFalse();
  }

  @Test
  void serializationDoesNotExposeConvenienceProperties() throws Exception {

    UserInfoResponse response = new UserInfoResponse(Map.of(SUB, "12345", "given_name", "John",
        "family_name", "Doe", "email", "john@example.org", "preferred_username", "jdoe"));

    JsonNode json = objectMapper.readTree(objectMapper.writeValueAsString(response));

    assertThat(json.has("name")).isFalse();
    assertThat(json.has("givenName")).isFalse();
    assertThat(json.has("familyName")).isFalse();
    assertThat(json.has("preferredUsername")).isFalse();

    assertThat(json.get("given_name").asText()).isEqualTo("John");
    assertThat(json.get("family_name").asText()).isEqualTo("Doe");
    assertThat(json.get("preferred_username").asText()).isEqualTo("jdoe");
  }

  @Test
  void constructorAcceptsClaimsParsedFromJson() throws Exception {

    String json = """
        {
          "sub": "248289761001",
          "given_name": "Jane",
          "family_name": "Doe",
          "email": "jane.doe@example.org",
          "preferred_username": "jdoe",
          "email_verified": true,
          "updated_at": 1672531200
        }
        """;

    ObjectMapper mapper = new ObjectMapper();

    Map<String, Object> claims = mapper.readValue(
        json,
        new TypeReference<Map<String, Object>>() {});

    UserInfoResponse response = new UserInfoResponse(claims);

    assertThat(response.getSub()).isEqualTo("248289761001");
    assertThat(response.getGivenName()).isEqualTo("Jane");
    assertThat(response.getFamilyName()).isEqualTo("Doe");
    assertThat(response.getEmail()).isEqualTo("jane.doe@example.org");
    assertThat(response.getPreferredUsername()).isEqualTo("jdoe");

    assertThat(response.getAdditionalFields())
        .containsEntry("email_verified", Boolean.TRUE)
        .containsEntry("updated_at", 1672531200)
        .doesNotContainKey("sub");
  }
}
