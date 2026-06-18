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
package it.infn.mw.iam.test.oauth.introspection;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
class IntrospectionEndpointAuthenticationTests extends EndpointsTestUtils {

  private String accessToken;

  @Autowired
  private IamClientRepository clientRepo;

  @BeforeEach
  void setup() throws Exception {
    accessToken = getPasswordToken("openid profile offline_access").accessToken();
  }


  @Test
  void testTokenIntrospectionEndpointBasicAuthentication() throws Exception {
    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on
  }

  @Test
  void testTokenIntrospectionEndpointFormAuthentication() throws Exception {
    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken)
        .param("client_id", PROTECTED_RESOURCE_ID)
        .param("client_secret", PROTECTED_RESOURCE_SECRET))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  void testTokenIntrospectionEndpointNoAuthenticationFailure() throws Exception {
    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isUnauthorized());
   // @formatter:on
  }

  @Test
  void testTokenIntrospectionEndpointWithDisabledClient() throws Exception {

    ClientDetailsEntity c = clientRepo.findByClientId(PROTECTED_RESOURCE_ID).orElseThrow();
    c.setActive(false);
    clientRepo.save(c);

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on

    c.setActive(true);
    clientRepo.save(c);
  }

  @Test
  void testTokenIntrospectionEndpointWithClientNotAllowedIntrospection() throws Exception {

    ClientDetailsEntity c = clientRepo.findByClientId(PROTECTED_RESOURCE_ID).orElseThrow();
    c.setAllowIntrospection(false);
    clientRepo.save(c);

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on

    c.setAllowIntrospection(true);
    clientRepo.save(c);
  }
}
