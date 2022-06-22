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
package it.infn.mw.iam.test.rcauth;


import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY;
import static it.infn.mw.iam.rcauth.DefaultRcAuthRequestService.RCAUTH_CTXT_SESSION_KEY;
import static it.infn.mw.iam.rcauth.RCAuthController.CALLBACK_PATH;
import static it.infn.mw.iam.rcauth.RCAuthController.GETCERT_PATH;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.http.MediaType.TEXT_PLAIN;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.rcauth.RCAuthExchangeContext;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.IdTokenBuilder;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;
import it.infn.mw.iam.test.util.oidc.TokenResponse;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, RCAuthTestConfig.class,
        RCAuthIntegrationTests.TestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(
    properties = {"rcauth.enabled=true", "rcauth.client-id=" + RCAuthTestSupport.CLIENT_ID,
        "rcauth.client-secret=" + RCAuthTestSupport.CLIENT_SECRET,
        "rcauth.issuer=" + RCAuthTestSupport.ISSUER})
public class RCAuthIntegrationTests extends RCAuthTestSupport {


  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    public RestTemplateFactory mockRestTemplateFactory() {
      return new MockRestTemplateFactory();
    }
  }

  @Autowired
  private RestTemplateFactory rtf;

  @Autowired
  private ObjectMapper mapper;

  private MockRestTemplateFactory mockRtf;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    mockRtf = (MockRestTemplateFactory) rtf;
    mockRtf.resetTemplate();
  }

  @Test
  @WithAnonymousUser
  public void rcAuthRequiresAuthenticatedUser() throws Exception {
    mvc.perform(get(GETCERT_PATH).with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL));
  }

  @Test
  @WithMockUser(username = "test")
  public void rcAuthWithUserSucceedsAndSetsSessionAttributes() throws Exception {

    MvcResult result = mvc.perform(get(GETCERT_PATH).with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(request().sessionAttribute(RCAUTH_CTXT_SESSION_KEY, notNullValue()))
      .andReturn();

    UriComponents uc =
        UriComponentsBuilder.fromHttpUrl(result.getResponse().getRedirectedUrl()).build();

    assertThat(uc.getHost(), is(RCAUTH_HOST));
  }

  @Test
  @WithMockUser(username = "test")
  public void rcAuthAuthorizationResponseValidation() throws Exception {

    mvc.perform(get(CALLBACK_PATH).with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          startsWith("Invalid RCAuth authorization response")));

    mvc.perform(get(CALLBACK_PATH).param("code", "a-code").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          startsWith("Invalid RCAuth authorization response")));

    mvc.perform(get(CALLBACK_PATH).param("state", "a-state").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          startsWith("Invalid RCAuth authorization response")));
  }

  @Test
  @WithMockUser(username = "test")
  public void rcAuthAuthorizationResponseInvalidContext() throws Exception {

    mvc
      .perform(get(CALLBACK_PATH).param("code", "a-code")
        .param("state", "a-state")
        .with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          startsWith("RCAuth error: RCAuth context not found in session")));
  }

  @Test
  @WithMockUser(username = "test")
  public void rcAuthFullLinking() throws Exception {
    MvcResult result = mvc.perform(get(GETCERT_PATH).with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(request().sessionAttribute(RCAUTH_CTXT_SESSION_KEY, notNullValue()))
      .andReturn();

    MockHttpSession session = (MockHttpSession) result.getRequest().getSession();


    RCAuthExchangeContext context =
        ((RCAuthExchangeContext) session.getAttribute(RCAUTH_CTXT_SESSION_KEY));

    prepareTokenResponse(NONCE);
    prepareCertificateResponse();

    mvc
      .perform(get(CALLBACK_PATH).session(session)
        .param("code", CODE_VALUE)
        .param("state", context.getState())
        .with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY,
          startsWith("Proxy certificate with subject")));

  }

  void prepareTokenResponse(String nonce) throws JsonProcessingException, JOSEException {
    IdTokenBuilder builder = new IdTokenBuilder(rcAuthKeyStore, jwsAlgo);

    String idToken = builder.sub(SUB).issuer(ISSUER).customClaim(CERT_SUBJECT_DN_CLAIM, DN).build();

    TokenResponse tr = new TokenResponse();
    tr.setAccessToken(UUID.randomUUID().toString());
    tr.setExpiresIn(3600);
    tr.setIdToken(idToken);

    mockRtf.getMockServer()
      .expect(requestTo(TOKEN_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(APPLICATION_FORM_URLENCODED_UTF8_VALUE))
      .andRespond(withSuccess(mapper.writeValueAsString(tr), MediaType.APPLICATION_JSON));
  }

  public void prepareCertificateResponse() {
    mockRtf.getMockServer()
      .expect(requestTo(GET_CERT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(APPLICATION_FORM_URLENCODED_UTF8_VALUE))
      .andRespond(withSuccess(TEST_0_CERT_STRING, TEXT_PLAIN));
  }

  void verifyMockServerCalls() {
    mockRtf.getMockServer().verify();
    mockRtf.resetTemplate();
  }
}
