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



import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class IntrospectionEndpointTests extends EndpointsTestUtils {

  @Value("${iam.organisation.name}")
  String organisationName;

  @Value("${iam.issuer}")
  String issuer;

  @Autowired
  IamClientRepository clientRepository;

  @Autowired
  IamAccountRepository accountRepository;

  @Autowired
  ObjectMapper mapper;

  @Test
  public void testIntrospectionEndpointReturnsBasicUserInformation() throws Exception {

    String accessToken = getPasswordAccessToken("openid");

    ClientDetailsEntity client = clientRepository.findByClientId(PASSWORD_CLIENT_ID).orElseThrow();
    IamAccount account = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    IntrospectionResponse response = mapper.readValue(mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param("token", accessToken)
            .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.sub", equalTo(account.getUuid())))
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.client_id").exists())
      .andExpect(jsonPath("$.client_id", equalTo(client.getClientId())))
      .andExpect(jsonPath("$.iss", equalTo(issuer)))
      .andExpect(jsonPath("$.exp").exists())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.given_name").doesNotExist())
      .andExpect(jsonPath("$.email").doesNotExist())
      .andReturn()
      .getResponse()
      .getContentAsString(), IntrospectionResponse.class);

    List<String> scopes =
        List.of(String.valueOf(response.getAdditionalFields().get("scope")).trim().split("\\s+"));
    assertEquals(1, scopes.size());
    assertEquals("openid", scopes.get(0));
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testIntrospectionEndpointWithRefreshToken() throws Exception {

    String refreshToken =
        getPasswordTokenResponse("openid profile offline_access").getRefreshToken().getValue();

    mvc
      .perform(
          post(INTROSPECTION_ENDPOINT).with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param("token", refreshToken)
            .param("token_type_hint", TokenTypeHint.REFRESH_TOKEN.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.exp", nullValue()))
      .andExpect(jsonPath("$.jti").exists());
  }

  @Test
  public void testNoGroupsReturnedWithoutProfileScope() throws Exception {
    String accessToken = getPasswordAccessToken("openid");

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.preferred_username").doesNotExist())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.email").doesNotExist())
      .andExpect(jsonPath("$.email_verified").doesNotExist());
    // @formatter:on
  }

  @Test
  public void testEmailReturnedWithEmailScope() throws Exception {
    String accessToken = getPasswordAccessToken("openid email");

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.given_name").doesNotExist())
      .andExpect(jsonPath("$.family_name").doesNotExist())
      .andExpect(jsonPath("$.middle_name").doesNotExist())
      .andExpect(jsonPath("$.nickname").doesNotExist())
      .andExpect(jsonPath("$.picture").doesNotExist())
      .andExpect(jsonPath("$.updated_at").doesNotExist())
      .andExpect(jsonPath("$.preferred_username").doesNotExist())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

  @Test
  public void testProfileClaimsReturnedWithProfileScope() throws Exception {
    String accessToken = getPasswordAccessToken("openid profile");
    IamAccount a = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name", equalTo(a.getUserInfo().getName())))
      .andExpect(jsonPath("$.given_name", equalTo(a.getUserInfo().getGivenName())))
      .andExpect(jsonPath("$.family_name", equalTo(a.getUserInfo().getFamilyName())))
      .andExpect(jsonPath("$.middle_name").doesNotExist())
      .andExpect(jsonPath("$.nickname", equalTo(a.getUserInfo().getNickname())))
      .andExpect(jsonPath("$.picture").doesNotExist())
      .andExpect(jsonPath("$.updated_at", equalTo(a.getLastUpdateTime().toString())))
      .andExpect(jsonPath("$.preferred_username", equalTo(a.getUsername())))
      .andExpect(jsonPath("$.affiliation", equalTo(a.getUserInfo().getAffiliation())))
      .andExpect(jsonPath("$.updated_at").exists())
      .andExpect(jsonPath("$.email").doesNotExist())
      .andExpect(jsonPath("$.email_verified").doesNotExist());
    // @formatter:on
  }
}
