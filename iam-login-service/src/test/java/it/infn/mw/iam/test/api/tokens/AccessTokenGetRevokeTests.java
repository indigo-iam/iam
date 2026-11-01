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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.test.util.TokenGetterUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.access_token.store_on_database=true"})
@AutoConfigureMockMvc
@Transactional
class AccessTokenGetRevokeTests extends TokenGetterUtils {

  static final int FAKE_TOKEN_ID = 12345;

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepository;

  @BeforeEach
  void setup() {
    accessTokenRepository.deleteAll();
  }

  private String createAccessTokenPath() throws Exception {

    assertThat(accessTokenRepository.count(), is(0L));

    getPasswordToken();

    assertThat(accessTokenRepository.count(), is(1L));

    Long id = accessTokenRepository.findAll().get(0).getId();

    return String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, id);
  }

  @Test
  void revokeAccessTokenForbiddenForUser() throws Exception {

    String path = createAccessTokenPath();

    mvc
      .perform(delete(path).with(user(TEST_USERNAME).roles("USER"))
        .with(csrf().asHeader())
        .contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isForbidden());

    assertThat(accessTokenRepository.count(), is(1L));
  }

  @Test
  void revokeAccessTokenAllowedForAdmin() throws Exception {

    String path = createAccessTokenPath();

    mvc
      .perform(delete(path).with(user(ADMIN_USERNAME).roles("ADMIN", "USER"))
        .with(csrf().asHeader())
        .contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    assertThat(accessTokenRepository.count(), is(0L));
  }

  @Test
  void revokeFakeAccessTokenGetsNoContent() throws Exception {

    assertThat(accessTokenRepository.count(), is(0L));

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);

    mvc
      .perform(
          delete(path).with(user(ADMIN_USERNAME).roles("ADMIN", "USER")).with(csrf().asHeader()))
      .andExpect(status().isNoContent());

    assertThat(accessTokenRepository.count(), is(0L));
  }

  @Test
  void revokeAccessTokenWithoutCsrfIsForbiddenForAdmin() throws Exception {

    String path = createAccessTokenPath();

    mvc
      .perform(delete(path).with(user(ADMIN_USERNAME).roles("ADMIN", "USER"))
        .contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isForbidden());

    assertThat(accessTokenRepository.count(), is(1L));
  }
}
