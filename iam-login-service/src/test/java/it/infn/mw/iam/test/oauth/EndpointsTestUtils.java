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
package it.infn.mw.iam.test.oauth;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SuppressWarnings("deprecation")
public class EndpointsTestUtils implements StructuredScopeTestSupportConstants {

  @Autowired
  protected ObjectMapper mapper;

  @Autowired
  protected MockMvc mvc;

  public AccessTokenGetter buildAccessTokenGetter() {
    return new AccessTokenGetter().grantType("password")
      .clientId(PASSWORD_CLIENT_ID)
      .clientSecret(PASSWORD_CLIENT_SECRET)
      .username(TEST_USERNAME)
      .password(TEST_PASSWORD);
  }

  protected DefaultOAuth2AccessToken getPasswordTokenResponse(String scope) throws Exception {

    AccessTokenGetter tg = buildAccessTokenGetter().scope(scope);
    return tg.getTokenResponseObject();
  }

  protected String getPasswordAccessToken(String scope) throws Exception {

    return getPasswordTokenResponse(scope).getValue();
  }

  protected String getPasswordAccessToken() throws Exception {
    return getPasswordAccessToken(EMPTY_SCOPES);
  }

  public class AccessTokenGetter {
    private String clientId;
    private String clientSecret;
    private String scope;
    private String grantType;
    private String username;
    private String password;
    private String audience;
    private String resource;
    private String claims;

    public AccessTokenGetter clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public AccessTokenGetter clientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public AccessTokenGetter scope(String scope) {
      this.scope = scope;
      return this;
    }

    public AccessTokenGetter grantType(String grantType) {
      this.grantType = grantType;
      return this;
    }

    public AccessTokenGetter username(String username) {
      this.username = username;
      return this;
    }

    public AccessTokenGetter password(String password) {
      this.password = password;
      return this;
    }

    public AccessTokenGetter audience(String audience) {
      this.audience = audience;
      return this;
    }

    public AccessTokenGetter resource(String resource) {
      this.resource = resource;
      return this;
    }

    public AccessTokenGetter claims(String claims) {
      this.claims = claims;
      return this;
    }

    public String performSuccessfulTokenRequest() throws Exception {

      return performTokenRequest(200).getResponse().getContentAsString();
    }

    public MvcResult performTokenRequest(int statusCode) throws Exception {
      MockHttpServletRequestBuilder req = post("/token").param("grant_type", grantType)
        .param("client_id", clientId)
        .param("client_secret", clientSecret);

      if (!isNullOrEmpty(scope)) {
        req.param("scope", scope);
      }

      if ("password".equals(grantType)) {
        req.param("username", username).param("password", password);
      }

      if (audience != null) {
        req.param("aud", audience);
      }

      if (resource != null) {
        req.param("resource", resource);
      }

      if (claims != null) {
        req.param("claims", claims);
      }

      return mvc.perform(req).andExpect(status().is(statusCode)).andReturn();
    }

    public DefaultOAuth2AccessToken getTokenResponseObject() throws Exception {

      String response = performSuccessfulTokenRequest();

      // This is incorrectly named in spring security OAuth, what they call OAuth2AccessToken
      // is a TokenResponse object
      DefaultOAuth2AccessToken tokenResponseObject =
          mapper.readValue(response, DefaultOAuth2AccessToken.class);

      return tokenResponseObject;
    }

    public String getAccessTokenValue() throws Exception {

      return getTokenResponseObject().getValue();
    }
  }
}
