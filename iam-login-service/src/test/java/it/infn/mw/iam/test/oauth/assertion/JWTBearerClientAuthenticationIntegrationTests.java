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
package it.infn.mw.iam.test.oauth.assertion;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class JWTBearerClientAuthenticationIntegrationTests
    extends JWTBearerClientAuthenticationIntegrationTestSupport {

  @Autowired
  IamProperties iamProperties;

  @Test
  void testSymmetricJwtAuthHasBeenDeprecated() throws Exception {

    JWT jwt = createSymmetricClientAuthToken(CLIENT_ID_SECRET_JWT, Instant.now().plusSeconds(600));
    String serializedToken = jwt.serialize();

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_SECRET_JWT)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error_description", is("SECRET_JWT has been deprecated")));
  }

  @Test
  void testAsymmetricJwtAuth() throws Exception {

    String serializedToken = createAsymmetricJwt(CLIENT_ID_PRIVATE_KEY_JWT);

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_PRIVATE_KEY_JWT)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists());

  }

  @Test
  void testAsymmetricJwtTokenEndpointWithLeadingSlash() throws Exception {

    iamProperties.setIssuer(TOKEN_ENDPOINT_AUDIENCE + "/");

    String serializedToken = createAsymmetricJwt(CLIENT_ID_PRIVATE_KEY_JWT);

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_PRIVATE_KEY_JWT)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists());

  }

  @Test
  void testAsymmetricJwtUnknownClientID() throws Exception {

    String serializedToken = createAsymmetricJwt(CLIENT_ID_PRIVATE_KEY_JWT);

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", "unknown")
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", is("invalid_client")))
      .andExpect(jsonPath("$.error_description",
          is("Given client ID does not match authenticated client")));
  }

  @Test
  void testAsymmetricUnknownJwt() throws Exception {

    final String CLIENT_ID_UNKNOWN = "unknown-client";
    String serializedToken = createAsymmetricJwt(CLIENT_ID_UNKNOWN);

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_PRIVATE_KEY_JWT)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", is("unauthorized")))
      .andExpect(jsonPath("$.error_description", is("Client not found")));
  }

  @Test
  void testAsymmetricUnknownJwtUnknownClient() throws Exception {

    final String CLIENT_ID_UNKNOWN = "unknown-client";
    String serializedToken = createAsymmetricJwt(CLIENT_ID_UNKNOWN);

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_UNKNOWN)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", is("unauthorized")))
      .andExpect(jsonPath("$.error_description", is("Client not found")));
  }

  @Test
  void testInvalidAssertionType() throws Exception {

    final String CLIENT_ID_UNKNOWN = "unknown-client";
    String serializedToken = createAsymmetricJwt(CLIENT_ID_UNKNOWN);

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_UNKNOWN)
        .param("client_assertion_type", "invalid-assertion-type")
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", is("invalid_client")))
      .andExpect(jsonPath("$.error_description", is("Bad client credentials")));
  }

}
