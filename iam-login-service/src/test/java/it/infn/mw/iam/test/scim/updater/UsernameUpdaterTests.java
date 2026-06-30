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
package it.infn.mw.iam.test.scim.updater;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;
import it.infn.mw.iam.test.api.tokens.MultiValueMapBuilder;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK, properties = {"iam.access_token.store_on_database=true"})
@AutoConfigureMockMvc
@Transactional
class UsernameUpdaterTests extends TokenGetterUtils {

  static final String OLD = "oldusername";
  static final String NEW = "newusername";

  @Autowired
  UsernameValidator usernameValidator;

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  IamAccountRepository accountRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  IamAccountService accountService;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  IamAccount account;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  private IamAccount newAccount(String username) {
    IamAccount account = new IamAccount();
    account.setUsername(username);
    account.setPassword("password");
    account.setActive(true);
    account.setUuid(UUID.randomUUID().toString());
    IamUserInfo userInfo = new IamUserInfo();
    userInfo.setEmail(String.format("%s@test.io", username));
    userInfo.setGivenName("test");
    userInfo.setFamilyName("user");
    userInfo.setSub(username);
    userInfo.setIamAccount(account);
    account.setUserInfo(userInfo);
    return accountService.createAccount(account);
  }

  private Replacers accountReplacers() {
    return AccountUpdaters.replacers(clock, accountRepository, accountService, encoder, account,
        accessTokenRepository, refreshTokenRepository, usernameValidator);
  }

  @Test
  void testUsernameReplacerWorks() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    account = newAccount(OLD);

    context.useLocalUser(OLD, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, OLD, "password",
        "openid offline_access");

    Updater u = accountReplacers().username(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    MultiValueMap<String, String> filterOldUsername =
        MultiValueMapBuilder.builder().userId(OLD).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> oldAccessTokens = getAccessTokenList(filterOldUsername);
    ListResponseDTO<RefreshToken> oldRefreshTokens = getRefreshTokenList(filterOldUsername);

    MultiValueMap<String, String> filterNewUsername =
        MultiValueMapBuilder.builder().userId(NEW).build();

    ListResponseDTO<AccessToken> newAccessTokens = getAccessTokenList(filterNewUsername);
    ListResponseDTO<RefreshToken> newRefreshTokens = getRefreshTokenList(filterNewUsername);

    assertEquals(0, oldAccessTokens.getResources().size());
    assertEquals(1, newAccessTokens.getResources().size());

    assertEquals(0, oldRefreshTokens.getResources().size());
    assertEquals(1, newRefreshTokens.getResources().size());

  }

}
