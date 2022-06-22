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
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Date;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.MultiValueMap;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.test.util.DateEqualModulo1Second;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class AccessTokenGetListTests extends TestTokensUtils {

  public static long id = 1L;

  public static final String[] SCOPES = {"openid", "profile"};
  public static final String[] SCOPES_REGISTRATION = {"registration-token"};
  public static final String[] SCOPES_RESOURCE = {"resource-token"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private IamOAuthAccessTokenRepository tokenRepository;

  private static final String TESTUSER_USERNAME = "test_102";
  private static final String TESTUSER2_USERNAME = "test_103";
  private static final String PARTIAL_USERNAME = "test_10";

  private static final String INJECTION_QUERY =
      "1%; DELETE FROM access_token; SELECT * FROM access_token WHERE userId LIKE %";

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
  public void getEmptyAccessTokenList() throws Exception {

    assertThat(tokenRepository.count(), equalTo(0L));

    /* get list */
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    /* get count */
    atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getNotEmptyAccessTokenListWithCountZero() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(tokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getAccessTokenListWithAttributes() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2AccessTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().attributes("user,idToken").build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(tokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.get(0);

    assertThat(remoteAt.getId(), equalTo(at.getId()));
    assertThat(remoteAt.getClient(), equalTo(null));
    assertThat(remoteAt.getExpiration(), equalTo(null));

    assertThat(remoteAt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteAt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteAt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  public void getAccessTokenListWithClientIdFilter() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    List<OAuth2AccessTokenEntity> accessTokens = Lists.newArrayList();
    OAuth2AccessTokenEntity target = buildAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    accessTokens.add(target);
    accessTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().clientId(client1.getClientId()).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.get(0);

    assertThat(remoteAt.getId(), equalTo(target.getId()));
    assertThat(remoteAt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteAt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteAt.getExpiration(), new DateEqualModulo1Second(target.getExpiration()));

    assertThat(remoteAt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteAt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteAt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  public void getAccessTokenListWithUserIdFilter() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    IamAccount user1 = loadTestUser(TESTUSER_USERNAME);

    List<OAuth2AccessTokenEntity> accessTokens = Lists.newArrayList();
    OAuth2AccessTokenEntity target = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    accessTokens.add(target);
    accessTokens.add(buildAccessToken(client, TESTUSER2_USERNAME, SCOPES));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(user1.getUsername()).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.get(0);

    assertThat(remoteAt.getId(), equalTo(target.getId()));
    assertThat(remoteAt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteAt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteAt.getExpiration(), new DateEqualModulo1Second(target.getExpiration()));

    assertThat(remoteAt.getUser().getId(), equalTo(user1.getUuid()));
    assertThat(remoteAt.getUser().getUserName(), equalTo(user1.getUsername()));
    assertThat(remoteAt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user1.getUuid())));
  }

  @Test
  public void getAccessTokenListWithFullClientIdAndUserIdFilter() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    IamAccount user1 = loadTestUser(TESTUSER_USERNAME);

    List<OAuth2AccessTokenEntity> accessTokens = Lists.newArrayList();
    OAuth2AccessTokenEntity target = buildAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    accessTokens.add(target);
    accessTokens.add(buildAccessToken(client1, TESTUSER2_USERNAME, SCOPES));
    accessTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES));
    accessTokens.add(buildAccessToken(client2, TESTUSER2_USERNAME, SCOPES));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder()
        .userId(user1.getUsername()).clientId(client1.getClientId()).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.get(0);

    assertThat(remoteAt.getId(), equalTo(target.getId()));
    assertThat(remoteAt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteAt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteAt.getExpiration(), new DateEqualModulo1Second(target.getExpiration()));

    assertThat(remoteAt.getUser().getId(), equalTo(user1.getUuid()));
    assertThat(remoteAt.getUser().getUserName(), equalTo(user1.getUsername()));
    assertThat(remoteAt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user1.getUuid())));
  }

  @Test
  public void getAccessTokenListWithPartialUserIdFilterReturnsEmpty() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client, TESTUSER2_USERNAME, SCOPES);

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(PARTIAL_USERNAME).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getAccessTokenListLimitedToPageSizeFirstPage() throws Exception {

    for (int i = 0; i < TOKENS_MAX_PAGE_SIZE; i++) {
      buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    }

    /* get first page */
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));
  }

  @Test
  public void getAccessTokenListLimitedToPageSizeSecondPage() throws Exception {

    for (int i = 0; i < TOKENS_MAX_PAGE_SIZE; i++) {
      buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    }

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().startIndex(TOKENS_MAX_PAGE_SIZE).build();

    /* get second page */
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));
  }

  @Test
  public void getAccessTokenListFilterUserIdInjection() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(INJECTION_QUERY).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));

    assertThat(tokenRepository.count(), equalTo(1L));
  }


  @Test
  public void getAccessTokenListWithOneClientCredentialAccessToken() throws Exception {

    buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    buildAccessToken(loadTestClient(TEST_CLIENT_ID), SCOPES);

    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
  }

  @Test
  public void getAllValidAccessTokensCountWithExpiredTokens() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildExpiredAccessToken(client, TESTUSER_USERNAME, SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }

  @Test
  public void getAllValidAccessTokensCountForUserWithExpiredTokens() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client, TESTUSER2_USERNAME, SCOPES);
    buildExpiredAccessToken(client, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(3L));

    Page<OAuth2AccessTokenEntity> tokens =
        tokenRepository.findAllValidAccessTokens(new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(2L));
    tokens.forEach(t -> System.out.println(t.getExpiration()));

    tokens = tokenRepository.findValidAccessTokensForUser(TESTUSER_USERNAME, new Date(),
        new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).userId(TESTUSER_USERNAME).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }

  @Test
  public void getAllValidAccessTokensCountForClientWithExpiredTokens() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    buildAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client2, TESTUSER_USERNAME, SCOPES);
    buildExpiredAccessToken(client1, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(3L));

    Page<OAuth2AccessTokenEntity> tokens =
        tokenRepository.findAllValidAccessTokens(new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(2L));
    tokens.forEach(t -> System.out.println(t.getExpiration()));

    tokens = tokenRepository.findValidAccessTokensForClient(TEST_CLIENT_ID, new Date(),
        new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).clientId(TEST_CLIENT_ID).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }


  @Test
  public void getAllValidAccessTokensCountForUserAndClientWithExpiredTokens() throws Exception {

    ClientDetailsEntity client1 = loadTestClient(TEST_CLIENT_ID);
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);

    buildAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client1, TESTUSER2_USERNAME, SCOPES);
    buildAccessToken(client2, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client2, TESTUSER2_USERNAME, SCOPES);
    buildExpiredAccessToken(client1, TESTUSER_USERNAME, SCOPES);
    buildExpiredAccessToken(client2, TESTUSER_USERNAME, SCOPES);
    buildExpiredAccessToken(client1, TESTUSER2_USERNAME, SCOPES);
    buildExpiredAccessToken(client2, TESTUSER2_USERNAME, SCOPES);

    assertThat(tokenRepository.count(), equalTo(8L));

    Page<OAuth2AccessTokenEntity> tokens =
        tokenRepository.findAllValidAccessTokens(new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(4L));
    tokens.forEach(t -> System.out.println(t.getExpiration()));

    tokens = tokenRepository.findValidAccessTokensForUserAndClient(TESTUSER_USERNAME,
        TEST_CLIENT_ID, new Date(), new OffsetPageable(0, 10));
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0)
        .userId(TESTUSER_USERNAME).clientId(TEST_CLIENT_ID).build();

    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }
  
  @Test
  public void getAccessTokenListWithoutRegistrationTokens() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);
    
    List<OAuth2AccessTokenEntity> accessTokens = Lists.newArrayList();
    
    OAuth2AccessTokenEntity at = buildAccessToken(client, null,
      SCOPES_REGISTRATION);
    
    accessTokens.add(at);
    
    ListResponseDTO<AccessToken> atl = getAccessTokenList();
    
    assertThat(tokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));

    accessTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES));
    
    atl = getAccessTokenList();
    
    assertThat(tokenRepository.count(), equalTo(2L));
    assertThat(atl.getTotalResults(), equalTo(1L));
  
    Page<OAuth2AccessTokenEntity> tokens =
        tokenRepository.findAllValidAccessTokens(new Date(), new OffsetPageable(0, 10));
    
    tokens.forEach(t -> assertThat(t.getScope(), not(hasItem("registration-token"))));
    
    
  }
    @Test public void getAccessTokenListWithoutResourceTokens() throws
    Exception {
    
    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID); 
    
    ClientDetailsEntity client2 = loadTestClient(TEST_CLIENT2_ID);
    
    List<OAuth2AccessTokenEntity> accessTokens = Lists.newArrayList();
    
    OAuth2AccessTokenEntity at = buildAccessToken(client, null,
    SCOPES_RESOURCE);

    accessTokens.add(at);
    
    ListResponseDTO<AccessToken> atl = getAccessTokenList();
    
    assertThat(tokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources() .size(), equalTo(0));
    
    accessTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES));
    
    atl = getAccessTokenList();
   
    assertThat(tokenRepository.count(), equalTo(2L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    
    Page<OAuth2AccessTokenEntity> tokens =
      tokenRepository.findAllValidAccessTokens(new Date(), new OffsetPageable(0, 10));
  
    tokens.forEach(t -> assertThat(t.getScope(), not(hasItem("resource-token"))));
    
    }
}
