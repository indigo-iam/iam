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
package it.infn.mw.iam.test.api.tokens;

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.APPLICATION_JSON_CONTENT_TYPE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class RefreshTokenAuthenticatedTests extends TestTokensUtils {

  private static final String TESTUSER_USERNAME = "test_102";
  private static final int FAKE_TOKEN_ID = 12345;
  
  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, authorities = {"ROLE_USER"})
  void forbiddenOnGettingListTest() throws Exception {

    mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(APPLICATION_JSON_CONTENT_TYPE)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, authorities = {"ROLE_USER"})
  void forbiddenOnRevokingTest() throws Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(APPLICATION_JSON_CONTENT_TYPE)).andExpect(status().isForbidden());
  }
}
