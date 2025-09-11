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
package it.infn.mw.iam.test.oauth.profile;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {
// @formatter:off
    "iam.jwt-profile.default-profile=kc",
    // @formatter:on
})
public class KeycloakProfileUserInfoTests extends EndpointsTestUtils {

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(clientId = PASSWORD_CLIENT_ID, user = TEST_USERNAME,
      authorities = {"ROLE_USER"}, scopes = {"openid profile"})
  public void testUserinfoResponseWithGroups() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.roles").exists())
      .andExpect(jsonPath("$.roles", hasSize(2)))
      .andExpect(jsonPath("$.roles", hasItems("Analysis", "Production")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = PASSWORD_CLIENT_ID, user = ADMIN_USERNAME,
      authorities = {"ROLE_USER"}, scopes = {"openid profile"})
  public void testUserinfoResponseForUserWithoutGroups() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.roles").doesNotExist());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = PASSWORD_CLIENT_ID, authorities = {"ROLE_CLIENT"},
      scopes = {"openid"})
  public void testUserinfoResponseWithoutUser() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isForbidden());
    // @formatter:on
  }
}
