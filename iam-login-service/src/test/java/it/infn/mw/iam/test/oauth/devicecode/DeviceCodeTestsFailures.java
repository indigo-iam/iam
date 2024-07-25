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
package it.infn.mw.iam.test.oauth.devicecode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)

public class DeviceCodeTestsFailures extends EndpointsTestUtils
    implements DeviceCodeTestsConstants {

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ConfigurationPropertiesBean config;

  @Test
  public void testDeviceCodeReturnsBadRequestForEmptyClientId() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", ""))
      .andExpect(status().isBadRequest())
      .andExpect(view().name("httpCodeView"));

  }

  @Test
  public void testDeviceCodeNotWorkForExpiredCode() throws Exception {

    ClientDetailsEntity entity = clientRepo.findByClientId(DEVICE_CODE_CLIENT_ID).orElseThrow();
    entity.setDeviceCodeValiditySeconds(null);
    clientRepo.save(entity);

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.expires_in").doesNotExist())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)));

    entity.setDeviceCodeValiditySeconds(600);
    clientRepo.save(entity);

  }

  @Test
  public void testDeviceCodeNotReturnCompleteUri() throws Exception {

    config.setAllowCompleteDeviceCodeUri(false);

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").doesNotExist())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)));

    config.setAllowCompleteDeviceCodeUri(true);

  }

  @Test
  public void testDeviceCodeWithParenthesisInRequestedScopesFails() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "op [en ]id"))
      .andExpect(status().isBadRequest())
      .andExpect(view().name("jsonErrorView"));

  }

  @Test
  public void testDeviceCodeFailsWhenVerificationUriHasSyntaxErrors() throws Exception {

    config.setIssuer("local host");

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID))
      .andExpect(status().isInternalServerError())
      .andExpect(view().name("httpCodeView"));

    config.setIssuer("http://localhost:8080/");

  }

  
}
