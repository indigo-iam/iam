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
package it.infn.mw.iam.test.ext_authn.saml.jit_account_provisioning;

import static java.lang.String.format;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.net.URI;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;
import it.infn.mw.iam.test.ext_authn.saml.jit_account_provisioning.JitTestConfig.CountAccountCreatedEventsListener;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.TokenResponse;
import it.infn.mw.iam.test.util.saml.SamlUtils;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, JitTestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"saml.jit-account-provisioning.enabled=true",
    "saml.jit-account-provisioning.trusted-idps=" + SamlAuthenticationTestSupport.DEFAULT_IDP_ID})
@Transactional
public class SamlJitAccountProvisioningTests extends SamlAuthenticationTestSupport {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";

  public static final String RESPONSE_TYPE_CODE = "code";
  public static final String AUTHORIZATION_ENDPOINT = "/authorize";
  public static final String CONSENT_ENDPOINT = "/oauth/confirm_access";
  public static final String SCOPE = "openid profile";

  public static final String TEST_USER_ID = "test";
  public static final String TEST_USER_PASSWORD = "password";

  @Autowired
  IamSamlJITAccountProvisioningProperties props;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  CountAccountCreatedEventsListener accountCreatedEventListener;

  @Test
  public void testLoadedConfiguration() {
    Assert.assertTrue(props.getEnabled());
  }

  @Before
  public void before() {
    accountCreatedEventListener.resetCount();
  }

  @Test
  public void testJITAccountProvisionAccountOnlyOnce() throws Throwable {

    MockHttpSession session =
        (MockHttpSession) mvc.perform(MockMvcRequestBuilders.get(samlDefaultIdpLoginUrl()))
          .andExpect(MockMvcResultMatchers.status().isOk())
          .andReturn()
          .getRequest()
          .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildJitTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(redirectedUrl("/dashboard"))
      .andReturn()
      .getRequest()
      .getSession();

    assertThat(accountCreatedEventListener.getCount(), equalTo(1L));

    mvc.perform(get("/dashboard").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/dashboard"));

    IamAccount provisionedAccount = accountRepo
      .findBySamlId(DEFAULT_IDP_ID, Saml2Attribute.EPUID.getAttributeName(), JIT1_EPUID)
      .orElseThrow(() -> new AssertionError(
          String.format("Expected provisioned account not found for EPUID '%s'", JIT1_EPUID)));

    assertThat(provisionedAccount.getUsername(), equalTo(JIT1_EPUID));
    assertThat(provisionedAccount.getUserInfo().getEmail(), equalTo(JIT1_MAIL));
    assertTrue(provisionedAccount.isActive());
    assertTrue(provisionedAccount.isProvisioned());
    assertThat(provisionedAccount.getUserInfo().getGivenName(), equalTo(JIT1_GIVEN_NAME));
    assertThat(provisionedAccount.getUserInfo().getFamilyName(), equalTo(JIT1_FAMILY_NAME));

    session = (MockHttpSession) mvc.perform(MockMvcRequestBuilders.get(samlDefaultIdpLoginUrl()))
      .andExpect(MockMvcResultMatchers.status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    r = buildJitTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(redirectedUrl("/dashboard"))
      .andReturn()
      .getRequest()
      .getSession();

    IamAccount newProvisionedAccount = accountRepo
      .findBySamlId(DEFAULT_IDP_ID, Saml2Attribute.EPUID.getAttributeName(), JIT1_EPUID)
      .orElseThrow(() -> new AssertionError(
          String.format("Expected provisioned account not found for EPUID '%s'", JIT1_EPUID)));

    assertThat(newProvisionedAccount.getUuid(), equalTo(provisionedAccount.getUuid()));
    assertThat(accountCreatedEventListener.getCount(), equalTo(1L));

  }

  @Test
  public void testAuthzCodeFlowWorksForJitProvisionedAccount() throws Throwable {

    UriComponents authorizationEndpointUri = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get(authorizationEndpointUri.toUriString()))
          .andExpect(status().is3xxRedirection())
          .andExpect(redirectedUrl(LOGIN_URL))
          .andReturn()
          .getRequest()
          .getSession();

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildJitTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(authorizationEndpointUri.encode().toUriString()))
      .andReturn()
      .getRequest()
      .getSession();

    assertThat(accountCreatedEventListener.getCount(), equalTo(1L));

    session =
        (MockHttpSession) mvc.perform(get(authorizationEndpointUri.toUriString()).session(session))
          .andExpect(status().isOk())
          .andExpect(forwardedUrl(CONSENT_ENDPOINT))
          .andReturn()
          .getRequest()
          .getSession();

    // Give consent
    MvcResult result = mvc
      .perform(post("/authorize").session(session)
        .param("user_oauth_approval", "true")
        .param("scope_openid", "openid")
        .param("scope_profile", "profile")
        .param("authorize", "Authorize")
        .param("remember", "none")
        .with(csrf()))
      .andExpect(status().is3xxRedirection())
      .andReturn();

    String redirectUrl = result.getResponse().getRedirectedUrl();
    session = (MockHttpSession) result.getRequest().getSession();

    assertThat(redirectUrl, startsWith(TEST_CLIENT_REDIRECT_URI));
    UriComponents redirectUri = UriComponentsBuilder.fromUri(new URI(redirectUrl)).build();
    String code = redirectUri.getQueryParams().getFirst("code");

    String tokenResponse =
        mvc
          .perform(
              post("/token").param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
                .with(SecurityMockMvcRequestPostProcessors.httpBasic(TEST_CLIENT_ID,
                    TEST_CLIENT_SECRET)))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString();

    TokenResponse response = objectMapper.readValue(tokenResponse, TokenResponse.class);

    String accessToken = response.getAccessToken();

    mvc.perform(get("/userinfo").header("Authorization", format("Bearer %s", accessToken)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.name", equalTo(format("%s %s", JIT1_GIVEN_NAME, JIT1_FAMILY_NAME))))
      .andExpect(jsonPath("$.external_authn.type", equalTo("saml")));
  }


  @Test
  public void testAuthzCodeFlowWithExtAuthnHintWorksForJitProvisionedAccount() throws Throwable {

    UriComponents authorizationEndpointUri = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .queryParam("ext_authn_hint", "saml:" + DEFAULT_IDP_ID)
      .build();

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get(authorizationEndpointUri.toUriString()))
          .andExpect(status().is3xxRedirection())
          .andExpect(redirectedUrl("http://localhost:8080/saml/login?idp=" + DEFAULT_IDP_ID))
          .andReturn()
          .getRequest()
          .getSession();

    session = (MockHttpSession) mvc.perform(get(samlDefaultIdpLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildJitTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(authorizationEndpointUri.encode().toUriString()))
      .andReturn()
      .getRequest()
      .getSession();

    assertThat(accountCreatedEventListener.getCount(), equalTo(1L));

    session =
        (MockHttpSession) mvc.perform(get(authorizationEndpointUri.toUriString()).session(session))
          .andExpect(status().isOk())
          .andExpect(forwardedUrl(CONSENT_ENDPOINT))
          .andReturn()
          .getRequest()
          .getSession();

    // Give consent
    MvcResult result = mvc
      .perform(post("/authorize").session(session)
        .param("user_oauth_approval", "true")
        .param("scope_openid", "openid")
        .param("scope_profile", "profile")
        .param("authorize", "Authorize")
        .param("remember", "none")
        .with(csrf()))
      .andExpect(status().is3xxRedirection())
      .andReturn();

    String redirectUrl = result.getResponse().getRedirectedUrl();
    session = (MockHttpSession) result.getRequest().getSession();

    assertThat(redirectUrl, startsWith(TEST_CLIENT_REDIRECT_URI));
    UriComponents redirectUri = UriComponentsBuilder.fromUri(new URI(redirectUrl)).build();
    String code = redirectUri.getQueryParams().getFirst("code");

    String tokenResponse =
        mvc
          .perform(
              post("/token").param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
                .with(SecurityMockMvcRequestPostProcessors.httpBasic(TEST_CLIENT_ID,
                    TEST_CLIENT_SECRET)))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString();

    TokenResponse response = objectMapper.readValue(tokenResponse, TokenResponse.class);

    String accessToken = response.getAccessToken();

    mvc.perform(get("/userinfo").header("Authorization", format("Bearer %s", accessToken)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.name", equalTo(format("%s %s", JIT1_GIVEN_NAME, JIT1_FAMILY_NAME))))
      .andExpect(jsonPath("$.external_authn.type", equalTo("saml")));
  }

}
