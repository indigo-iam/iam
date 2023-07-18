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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.registration.validation.UsernameValidator;
import it.infn.mw.iam.test.api.tokens.MultiValueMapBuilder;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
public class UsernameUpdaterTests extends TestTokensUtils {

  public static final String OLD = "oldusername";
  public static final String NEW = "newusername";
  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  private IamAccount account;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private UsernameValidator usernameValidator;

  @Before
  public void setup() {
    clearAllTokens();
    mockOAuth2Filter.cleanupSecurityContext();
    accessTokenRepository.deleteAll();
  }

  @After
  public void cleanupOAuthUser() {
    clearAllTokens();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private IamAccount newAccount(String username) {
    IamAccount account = new IamAccount();
    account.setUsername(username);
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
    return AccountUpdaters.replacers(accountRepository, accountService, encoder, account,
        tokenService, usernameValidator);
  }

  @Test
  public void testUsernameReplacerWorks() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    account = newAccount(OLD);

    buildAccessToken(loadTestClient(TEST_CLIENT_ID), OLD, SCOPES);
    assertThat(accessTokenRepository.count(), equalTo(1L));

    Updater u = accountReplacers().username(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    MultiValueMap<String, String> filterOldUsername =
        MultiValueMapBuilder.builder().userId(OLD).build();
    ListResponseDTO<AccessToken> oldAccessTokens = getAccessTokenList(filterOldUsername);
    ListResponseDTO<RefreshToken> oldRefreshTokens = getRefreshTokenList(filterOldUsername);

    MultiValueMap<String, String> filterNewUsername =
        MultiValueMapBuilder.builder().userId(NEW).build();
    ListResponseDTO<AccessToken> newAccessTokens = getAccessTokenList(filterNewUsername);
    ListResponseDTO<RefreshToken> newRefreshTokens = getRefreshTokenList(filterNewUsername);

    assertThat(oldAccessTokens.getTotalResults(), is(0L));
    assertThat(newAccessTokens.getTotalResults(), is(1L));

    assertThat(oldRefreshTokens.getTotalResults(), is(0L));
    assertThat(newRefreshTokens.getTotalResults(), is(1L));

  }

}
