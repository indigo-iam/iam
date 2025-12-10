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
package it.infn.mw.iam.test.service;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class IamAccountServiceIntegrationTests extends EndpointsTestUtils {

  private IamAccount testUser;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepo;

  @BeforeEach
  void setupUser() {

    testUser = IamAccount.newAccount();
    testUser.setActive(true);
    testUser.setUsername("test-user-info");
    testUser.setPassword("password");
    testUser.getUserInfo().setEmail("test.user.info@example.org");
    testUser.getUserInfo().setEmailVerified(true);
    testUser.getUserInfo().setGivenName("test");
    testUser.getUserInfo().setFamilyName("test");

    testUser = accountService.createAccount(testUser);
  }

  private TokenEndpointResponse requestTokens(String scopes) throws Exception {

    return parseTokens(new AccessTokenGetter().grantType("password")
      .clientId(PASSWORD_CLIENT_ID)
      .clientSecret(PASSWORD_CLIENT_SECRET)
      .username("test-user-info")
      .password("password")
      .scope(scopes)
      .getTokenResponseObject());
  }

  @Test
  void testTokensAreRemovedWhenAccountIsRemoved() throws Exception {

    TokenEndpointResponse tokenResponse = requestTokens("openid offline_access");
    String at1 = IamTokenService.sha256(tokenResponse.accessToken());
    tokenResponse = requestTokens("openid offline_access");
    String at2 = IamTokenService.sha256(tokenResponse.accessToken());

    accountService.deleteAccount(testUser);
    assertThat(accessTokenRepo.findByTokenValue(at1).isPresent(), is(false));
    assertThat(accessTokenRepo.findByTokenValue(at2).isPresent(), is(false));
    assertThat(refreshTokenRepo.findRefreshTokensForUser(testUser.getUsername()).isEmpty(),
        is(true));
  }
}
