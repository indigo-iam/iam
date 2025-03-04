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

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Collection;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class DeviceCodeApprovalTests extends EndpointsTestUtils
    implements DeviceCodeTestsConstants {

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ConfigurationPropertiesBean config;

  @Autowired
  private ApprovedSiteService approvedSiteService;


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
  public void testParenthesisInRequestedScopesDoesNotMatchAllowedScopes() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "op [en ]id"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_scope")));

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

  @Test
  public void testDeviceCodeVerificationUriCompleteWithoutUserCodeFails() throws Exception {

    mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").exists())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(WRONG_VERIFICATION_URI_COMPLETE))
      .andExpect(status().is3xxRedirection())
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(LOGIN_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get(WRONG_VERIFICATION_URI_COMPLETE).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("requestUserCode"));

  }

  @Test
  public void testDeviceCodeVerificationUriCompleteWorks() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").exists())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);

    String verificationUriComplete = responseJson.get("verification_uri_complete").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(verificationUriComplete))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(verificationUriComplete))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get(verificationUriComplete).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"));

  }

  @Test
  public void testDeviceCodeWithExpiredCodeFails() throws Exception {

    ClientDetailsEntity entity = clientRepo.findByClientId(DEVICE_CODE_CLIENT_ID).orElseThrow();
    entity.setDeviceCodeValiditySeconds(-1);
    clientRepo.save(entity);

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").exists())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);

    String verificationUriComplete = responseJson.get("verification_uri_complete").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(verificationUriComplete))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(verificationUriComplete))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get(verificationUriComplete).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("requestUserCode"));

    entity.setDeviceCodeValiditySeconds(600);
    clientRepo.save(entity);

  }

  @Test
  public void testAlreadyApprovedDeviceCodeFailsCodeVerification() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").exists())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);

    String verificationUriComplete = responseJson.get("verification_uri_complete").asText();
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(verificationUriComplete))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(verificationUriComplete))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(verificationUriComplete).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get(verificationUriComplete).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("requestUserCode"));

  }

  @Test
  public void testUserCodeMismatch() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").exists())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);

    String verificationUriComplete = responseJson.get("verification_uri_complete").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(verificationUriComplete))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(verificationUriComplete))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(verificationUriComplete).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", "1234")
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("requestUserCode"));

  }

  @Test
  public void testExpiredDeviceCodeFailsUserApproval() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", DEVICE_CODE_CLIENT_ID)
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri_complete").exists())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);

    String verificationUriComplete = responseJson.get("verification_uri_complete").asText();
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(verificationUriComplete))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(verificationUriComplete))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(verificationUriComplete).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    DeviceCode dc = (DeviceCode) session.getAttribute("deviceCode");
    dc.setExpiration(new Date());
    session.setAttribute("deviceCode", dc);

    mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("requestUserCode"));
  }

  @Test
  public void testNormalClientNotLinkedToUser() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/iam/account/me/clients").session(session))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.Resources", is(empty())));


  }

  @Test
  public void testRememberParameterAllowsToAddAnApprovedSite() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "until-revoked")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/api/approved").session(session))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].userId", is(TEST_USERNAME)))
      .andExpect(jsonPath("$[0].clientId", is(DEVICE_CODE_CLIENT_ID)))
      .andExpect(jsonPath("$[0].timeoutDate", nullValue()));

  }

  @Test
  public void testNoneRememberParameterDoesNotAddAnApprovedSite() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "none")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"));

    Collection<ApprovedSite> approvedSites =
        approvedSiteService.getByClientIdAndUserId(DEVICE_CODE_CLIENT_ID, TEST_USERNAME);

    assertTrue(approvedSites.isEmpty());

  }

  @Test
  public void testAddAnApprovedSiteFor1Hour() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "one-hour")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/api/approved").session(session))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].userId", is(TEST_USERNAME)))
      .andExpect(jsonPath("$[0].clientId", is(DEVICE_CODE_CLIENT_ID)))
      .andExpect(jsonPath("$[0].timeoutDate", notNullValue()));

  }

  @Test
  public void testAlreadyApprovedSiteSkipsConsentPage() throws Exception {

    String response = mvc
        .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
          .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
          .param("client_id", "device-code-client")
          .param("scope", "openid profile offline_access"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.user_code").isString())
        .andExpect(jsonPath("$.device_code").isString())
        .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
        .andReturn()
        .getResponse()
        .getContentAsString();

      JsonNode responseJson = mapper.readTree(response);
      String userCode = responseJson.get("user_code").asText();

      MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("http://localhost:8080/login"))
        .andReturn()
        .getRequest()
        .getSession();

      session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
        .andExpect(status().isOk())
        .andExpect(view().name("iam/login"))
        .andReturn()
        .getRequest()
        .getSession();

      session = (MockHttpSession) mvc
        .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
          .param("password", TEST_PASSWORD)
          .param("submit", "Login")
          .session(session))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl(DEVICE_USER_URL))
        .andReturn()
        .getRequest()
        .getSession();

      session = (MockHttpSession) mvc
        .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
        .andExpect(status().isOk())
        .andExpect(view().name("iam/approveDevice"))
        .andReturn()
        .getRequest()
        .getSession();

      session = (MockHttpSession) mvc
        .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
          .param("user_oauth_approval", "true")
          .param("remember", "until-revoked")
          .session(session))
        .andExpect(status().isOk())
        .andExpect(view().name("deviceApproved"))
        .andReturn()
        .getRequest()
        .getSession();

      response = mvc
        .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
          .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
          .param("client_id", "device-code-client")
          .param("scope", "openid profile offline_access"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.user_code").isString())
        .andExpect(jsonPath("$.device_code").isString())
        .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
        .andReturn()
        .getResponse()
        .getContentAsString();

      responseJson = mapper.readTree(response);
      userCode = responseJson.get("user_code").asText();

      mvc.perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
        .andExpect(status().isOk())
        .andExpect(view().name("deviceApproved"));
  }

  @Test
  public void testAlreadyApprovedSiteAllowsIssuingAT() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "until-revoked")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();
    
    mvc
    .perform(
        post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
          .param("grant_type", DEVICE_CODE_GRANT_TYPE)
          .param("device_code", deviceCode))
    .andExpect(status().isOk())
    .andExpect(jsonPath("$.scope", containsString("openid")))
    .andExpect(jsonPath("$.scope", containsString("profile")))
    .andExpect(jsonPath("$.scope", containsString("offline_access")));

    response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    responseJson = mapper.readTree(response);
    userCode = responseJson.get("user_code").asText();
    deviceCode = responseJson.get("device_code").asText();

    mvc.perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"));
    
    mvc
    .perform(
        post(TOKEN_ENDPOINT).with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
          .param("grant_type", DEVICE_CODE_GRANT_TYPE)
          .param("device_code", deviceCode))
    .andExpect(status().isOk())
    .andExpect(jsonPath("$.scope", containsString("openid")))
    .andExpect(jsonPath("$.scope", containsString("profile")))
    .andExpect(jsonPath("$.scope", containsString("offline_access")));

  }

  @Test
  public void testNewRequestedScopePromptToConsentPage() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "until-revoked")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    responseJson = mapper.readTree(response);
    userCode = responseJson.get("user_code").asText();

    mvc.perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"));

  }

  @Test
  public void testASubsetOfApprovedScopesUpdatesApprovedSiteAccessDate() throws Exception {

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/approveDevice"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(DEVICE_USER_APPROVE_URL).param("user_code", userCode)
        .param("user_oauth_approval", "true")
        .param("remember", "until-revoked")
        .session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"))
      .andReturn()
      .getRequest()
      .getSession();

    response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    responseJson = mapper.readTree(response);
    userCode = responseJson.get("user_code").asText();

    Thread.sleep(1000);

    mvc.perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"));

    response = mvc.perform(get("/api/approved").session(session))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].userId", is(TEST_USERNAME)))
      .andExpect(jsonPath("$[0].clientId", is(DEVICE_CODE_CLIENT_ID)))
      .andExpect(jsonPath("$[0].timeoutDate", nullValue()))
      .andExpect(jsonPath("$[0].creationDate", notNullValue()))
      .andExpect(jsonPath("$[0].accessDate", notNullValue()))
      .andReturn()
      .getResponse()
      .getContentAsString();

    responseJson = mapper.readTree(response);
    assertNotEquals(responseJson.get(0).get("accessDate"), responseJson.get(0).get("creationDate"));

  }

}
