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
package it.infn.mw.iam.test.oauth.userinfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.userinfo.UserInfoResponse;

class UserInfoResponseTests {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void shouldDeserializeOidcUserInfoResponse() throws Exception {

    String json = """
        {
          "sub": "248289761001",
          "name": "Jane Doe",
          "given_name": "Jane",
          "middle_name": "Mary",
          "family_name": "Doe",
          "preferred_username": "jdoe",
          "email": "jane@example.org",
          "email_verified": true,
          "groups": [
            "users",
            "developers"
          ],
          "custom_claim": "custom-value"
        }
        """;

    UserInfoResponse response = objectMapper.readValue(json, UserInfoResponse.class);

    assertThat(response).isNotNull();

    assertThat(response.getSub()).isEqualTo("248289761001");
    assertThat(response.getGivenName()).isEqualTo("Jane");
    assertThat(response.getFamilyName()).isEqualTo("Doe");
    assertThat(response.getPreferredUsername()).isEqualTo("jdoe");
    assertThat(response.getEmail()).isEqualTo("jane@example.org");
    assertThat(response.getName()).isEqualTo("Jane Mary Doe");

    assertThat(response.getAdditionalFields()).containsEntry("given_name", "Jane")
      .containsEntry("middle_name", "Mary")
      .containsEntry("family_name", "Doe")
      .containsEntry("preferred_username", "jdoe")
      .containsEntry("email", "jane@example.org")
      .containsEntry("email_verified", true)
      .containsEntry("custom_claim", "custom-value");

    assertThat(response.getAdditionalFields()).doesNotContainKey("sub");

    assertThat(response.getAdditionalFields()).containsEntry("groups",
        List.of("users", "developers"));
  }

  @Test
  void shouldRejectUserInfoResponseWithoutSub() {

    String json = """
        {
          "given_name": "Jane",
          "family_name": "Doe",
          "email": "jane@example.org"
        }
        """;

    assertThatThrownBy(() -> objectMapper.readValue(json, UserInfoResponse.class))
      .hasRootCauseInstanceOf(NullPointerException.class)
      .hasRootCauseMessage(UserInfoResponse.MISSING_SUB_ERROR);
  }
}
