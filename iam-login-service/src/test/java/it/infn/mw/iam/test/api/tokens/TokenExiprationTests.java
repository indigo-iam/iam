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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class TokenExiprationTests extends TokenGetterUtils {

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  @Test
  void tokenExchangeUpscopingExpiredTokenFail() throws Exception {

    context.useLocalTestUser();
    String subjectToken = getPasswordToken().accessToken();
    clock.advance(Duration.ofHours(12));

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", subjectToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
        .param("scope", "profile"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("invalid_token"))
      .andExpect(jsonPath("$.error_description").value("The access token is expired"));
  }
}
