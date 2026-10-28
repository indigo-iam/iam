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
package it.infn.mw.iam.test.oauth.userinfo;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.TokenGetterUtils;

@SpringBootTest(classes = IamLoginService.class, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class UserInfoHttpMethodsTests extends TokenGetterUtils {

  @ParameterizedTest
  @EnumSource(value = HttpMethod.class, names = {"GET", "POST"})
  void userInfoAcceptsBearerTokenWithoutCsrf(HttpMethod method) throws Exception {

    String accessToken = getPasswordToken("openid").accessToken();

    mvc
      .perform(
          request(method, "/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.sub").value(TEST_UUID));
  }

  @ParameterizedTest
  @EnumSource(value = HttpMethod.class, names = {"GET", "POST"})
  void userInfoRejectsInvalidBearerToken(HttpMethod method) throws Exception {

    mvc
      .perform(
          request(method, "/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isUnauthorized());
  }
}
