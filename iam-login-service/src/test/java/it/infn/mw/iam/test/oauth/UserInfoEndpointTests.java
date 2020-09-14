/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@Transactional
public class UserInfoEndpointTests {

  @Autowired
  private WebApplicationContext context;

  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;


  @Before
  public void setup() throws Exception {
    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred", scopes = {"openid"})
  public void testUserInfoEndpointReturs404ForClientCredentialsToken() throws Exception {
    mvc.perform(get("/userinfo")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid"})
  public void testUserInfoEndpointRetursOk() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.*", Matchers.hasSize(1)))
      .andExpect(jsonPath("$.sub").exists());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  public void testUserInfoEndpointRetursAllExpectedInfo() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name", is("indigo-dc")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"}, externallyAuthenticated = true,
      externalAuthenticationType = ExternalAuthenticationType.OIDC)
  public void testUserInfoEndpointRetursExtAuthnClaim() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.external_authn").exists());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  public void userinfoEndpointReturnsUpdatedAtClaimAsANumber() throws Exception {

    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.updated_at").isNumber());
  }

}
