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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

@SuppressWarnings("deprecation")
public class EndpointsTestUtils {

  private static final String DEFAULT_USERNAME = "test";
  private static final String DEFAULT_PASSWORD = "password";
  private static final String DEFAULT_CLIENT_ID = "password-grant";
  private static final String DEFAULT_CLIENT_SECRET = "secret";
  private static final String DEFAULT_SCOPE = "";

  @Autowired
  protected ObjectMapper mapper;

  @Autowired
  protected MockMvc mvc;

  public AccessTokenGetter buildAccessTokenGetter() {
    return new AccessTokenGetter().grantType("password")
      .clientId(DEFAULT_CLIENT_ID)
      .clientSecret(DEFAULT_CLIENT_SECRET)
      .username(DEFAULT_USERNAME)
      .password(DEFAULT_PASSWORD);
  }

  protected String getPasswordAccessToken(String scope) throws Exception {

    AccessTokenGetter tg = buildAccessTokenGetter().scope(scope);
    return tg.getAccessTokenValue();
  }

  protected String getPasswordAccessToken() throws Exception {
    return getPasswordAccessToken(DEFAULT_SCOPE);
  }

  public class AccessTokenGetter {
    private String clientId;
    private String clientSecret;
    private String scope;
    private String grantType;
    private String username;
    private String password;
    private String audience;

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

    public String performTokenRequest() throws Exception {
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

      String response = mvc.perform(req)
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();

      return response;
    }

    public DefaultOAuth2AccessToken getTokenResponseObject() throws Exception {

      String response = performTokenRequest();

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
