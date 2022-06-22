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

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.TOKENS_MAX_PAGE_SIZE;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Date;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.MultiValueMap;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class RefreshTokenGetListTests extends TestTokensUtils {

  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;
  private static final String TESTUSER_USERNAME = "test_102";
  private static final String TESTUSER2_USERNAME = "test_103";
  private static final String PARTIAL_USERNAME = "test_10";

  private static final String INJECTION_QUERY =
      "1%; DELETE FROM access_token; SELECT * FROM refresh_token WHERE userId LIKE %";

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private IamOAuthRefreshTokenRepository tokenRepository;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() {
    clearAllTokens();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    clearAllTokens();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void getEmptyRefreshTokenList() throws Exception {

    assertThat(tokenRepository.count(), equalTo(0L));

    /* get list */
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList();

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    /* get count */
    atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getNotEmptyRefreshTokenListWithCountZero() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(tokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getRefreshTokenListWithAttributes() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2RefreshTokenEntity at =
        buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().attributes("user,idToken").build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(tokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    RefreshToken remoteRt = atl.getResources().get(0);

    assertThat(remoteRt.getId(), equalTo(at.getId()));
    assertThat(remoteRt.getClient(), equalTo(null));
    assertThat(remoteRt.getExpiration(), equalTo(null));
    assertThat(remoteRt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteRt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteRt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  public void getRefreshTokenListWithClientIdFilter() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    List<OAuth2RefreshTokenEntity> refreshTokens = Lists.newArrayList();
    OAuth2RefreshTokenEntity target =
        buildAccessToken(client1, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    refreshTokens.add(target);
    refreshTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES).getRefreshToken());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().clientId(client1.getClientId()).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    RefreshToken remoteRt = atl.getResources().get(0);

    assertThat(remoteRt.getId(), equalTo(target.getId()));
    assertThat(remoteRt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteRt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteRt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteRt.getExpiration(), equalTo(target.getExpiration()));
    assertThat(remoteRt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteRt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteRt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  public void getRefreshTokenListWithUserIdFilter() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    IamAccount user1 = loadTestUser(TESTUSER_USERNAME);

    List<OAuth2RefreshTokenEntity> refreshTokens = Lists.newArrayList();
    OAuth2RefreshTokenEntity target =
        buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    refreshTokens.add(target);
    refreshTokens.add(buildAccessToken(client, TESTUSER2_USERNAME, SCOPES).getRefreshToken());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(user1.getUsername()).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    RefreshToken remoteRt = atl.getResources().get(0);

    assertThat(remoteRt.getId(), equalTo(target.getId()));
    assertThat(remoteRt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteRt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteRt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteRt.getExpiration(), equalTo(target.getExpiration()));
    assertThat(remoteRt.getUser().getId(), equalTo(user1.getUuid()));
    assertThat(remoteRt.getUser().getUserName(), equalTo(user1.getUsername()));
    assertThat(remoteRt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user1.getUuid())));
  }

  @Test
  public void getRefreshTokenListWithClientIdAndUserIdFilter() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    IamAccount user1 = loadTestUser(TESTUSER_USERNAME);

    List<OAuth2RefreshTokenEntity> refreshTokens = Lists.newArrayList();
    OAuth2RefreshTokenEntity target =
        buildAccessToken(client1, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    refreshTokens.add(target);
    refreshTokens.add(buildAccessToken(client1, TESTUSER2_USERNAME, SCOPES).getRefreshToken());
    refreshTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES).getRefreshToken());
    refreshTokens.add(buildAccessToken(client2, TESTUSER2_USERNAME, SCOPES).getRefreshToken());

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder()
        .userId(user1.getUsername()).clientId(client1.getClientId()).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    RefreshToken remoteRt = atl.getResources().get(0);

    assertThat(remoteRt.getId(), equalTo(target.getId()));
    assertThat(remoteRt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteRt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteRt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteRt.getExpiration(), equalTo(target.getExpiration()));
    assertThat(remoteRt.getUser().getId(), equalTo(user1.getUuid()));
    assertThat(remoteRt.getUser().getUserName(), equalTo(user1.getUsername()));
    assertThat(remoteRt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user1.getUuid())));
  }

  @Test
  public void getRefreshTokenListWithPartialUserIdFilterReturnsEmpty() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client, TESTUSER2_USERNAME, SCOPES);

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(PARTIAL_USERNAME).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getRefreshTokenListLimitedToPageSizeFirstPage() throws Exception {

    for (int i = 0; i < 2 * TOKENS_MAX_PAGE_SIZE; i++) {
      buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    }

    /* get first page */
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList();

    assertThat(atl.getTotalResults(), equalTo(2L * TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));
  }

  @Test
  public void getRefreshTokenListLimitedToPageSizeSecondPage() throws Exception {

    for (int i = 0; i < 2 * TOKENS_MAX_PAGE_SIZE; i++) {
      buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    }

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().startIndex(TOKENS_MAX_PAGE_SIZE).build();

    /* get second page */
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L * TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getStartIndex(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getItemsPerPage(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));
  }

  @Test
  public void getRefreshTokenListFilterUserIdInjection() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(INJECTION_QUERY).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));

    assertThat(tokenRepository.count(), equalTo(1L));
  }

  @Test
  public void getAllValidRefreshTokensCountWithExpiredTokens() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client, TESTUSER_USERNAME, SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }

  @Test
  public void getAllValidRefreshTokensCountForUserWithExpiredTokens() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client, TESTUSER2_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(3L));

    Page<OAuth2RefreshTokenEntity> tokens =
        tokenRepository.findAllValidRefreshTokens(new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(2L));
    tokens.forEach(t -> System.out.println(t.getExpiration()));

    tokens = tokenRepository.findValidRefreshTokensForUser(TESTUSER_USERNAME, new Date(),
        new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).userId(TESTUSER_USERNAME).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }

  @Test
  public void getAllValidRefreshTokensCountForClientWithExpiredTokens() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    buildAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client2, TESTUSER_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client1, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(3L));

    Page<OAuth2RefreshTokenEntity> tokens =
        tokenRepository.findAllValidRefreshTokens(new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(2L));
    tokens.forEach(t -> System.out.println(t.getExpiration()));

    tokens = tokenRepository.findValidRefreshTokensForClient(TEST_CLIENT_ID, new Date(),
        new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).clientId(TEST_CLIENT_ID).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }


  @Test
  public void getAllValidRefreshTokensCountForUserAndClientWithExpiredTokens() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    buildAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client1, TESTUSER2_USERNAME, SCOPES);
    buildAccessToken(client2, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client2, TESTUSER2_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client1, TESTUSER_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client2, TESTUSER_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client1, TESTUSER2_USERNAME, SCOPES);
    buildAccessTokenWithExpiredRefreshToken(client2, TESTUSER2_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(8L));

    Page<OAuth2RefreshTokenEntity> tokens =
        tokenRepository.findAllValidRefreshTokens(new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(4L));
    tokens.forEach(t -> System.out.println(t.getExpiration()));

    tokens = tokenRepository.findValidRefreshTokensForUserAndClient(TESTUSER_USERNAME,
        TEST_CLIENT_ID, new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0)
        .userId(TESTUSER_USERNAME).clientId(TEST_CLIENT_ID).build();

    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }
}
