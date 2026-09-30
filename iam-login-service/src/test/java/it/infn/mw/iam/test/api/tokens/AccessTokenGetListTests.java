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
import static it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest.MAX_PAGE_SIZE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
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
class AccessTokenGetListTests extends TokenGetterUtils {

  static final String[] SCOPES = {"openid", "profile"};

  static final String INJECTION_QUERY =
      "1%; DELETE FROM access_token; SELECT * FROM access_token WHERE userId LIKE %";

  static final Pageable FIRST_10 = new OffsetPageable(0, 10);
  static final String DEFAULT_SCOPES = "openid";

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  @PersistenceContext
  EntityManager entityManager;

  @BeforeEach
  void initSecurityContext() {
    context.cleanupSecurityContext();
    accessTokenRepository.deleteAll();
  }

  @Test
  void forbiddenAccessTokenList() throws Exception {

    /* get list */
    context.useBearerTestToken(new String[] {"openid", "profile"});
    mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isForbidden());
  }

  @Test
  void getEmptyAccessTokenList() throws Exception {

    assertEquals(0L, accessTokenRepository.count());

    /* get list */
    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertEquals(0L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
    assertEquals(0, atl.getResources().size());

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    /* get count */
    atl = getAccessTokenList(params);

    assertEquals(0L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
    assertEquals(0, atl.getResources().size());
  }

  @Test
  void getNotEmptyAccessTokenListWithCountZero() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(1L, accessTokenRepository.count());
    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
    assertEquals(0, atl.getResources().size());
  }

  @Test
  void getAccessTokenListWithClientIdFilter() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    getPasswordToken(DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);

    assertEquals(3L, accessTokenRepository.count());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(2L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(2, atl.getItemsPerPage());
    assertEquals(2, atl.getResources().size());

    atl.getResources().forEach(at -> assertEquals(PASSWORD_CLIENT_ID, at.clientId()));
  }

  @Test
  void getAccessTokenListWithUserIdFilter() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES).accessToken();
    getPasswordToken(DEFAULT_SCOPES).accessToken();
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertEquals(3L, accessTokenRepository.count());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(2L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(2, atl.getItemsPerPage());
    assertEquals(2, atl.getResources().size());

    atl.getResources().forEach(at -> {
      assertEquals(TEST_USERNAME, at.user().username());
      assertEquals(scimResourceLocationProvider.userLocation(TEST_UUID), at.user().ref());
    });
  }

  @Test
  void getAccessTokenListWithFullClientIdAndUserIdFilter() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);

    assertEquals(3L, accessTokenRepository.count());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(1, atl.getItemsPerPage());
    assertEquals(1, atl.getResources().size());

    atl.getResources().forEach(at -> {
      assertEquals(PASSWORD_CLIENT_ID, at.clientId());
      assertEquals(TEST_USERNAME, at.user().username());
      assertEquals(scimResourceLocationProvider.userLocation(TEST_UUID), at.user().ref());
    });
  }

  @Test
  void getAccessTokenListWithPartialUserIdFilterReturnsEmpty() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertEquals(2L, accessTokenRepository.count());

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().userId("tes").build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(0L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
    assertEquals(0, atl.getResources().size());
  }

  @Test
  void getAccessTokenListLimitedToPageSizeFirstPage() throws Exception {

    context.useLocalTestUser();
    for (int i = 0; i < MAX_PAGE_SIZE; i++) {
      getPasswordToken(DEFAULT_SCOPES);
    }

    assertEquals(Long.valueOf(MAX_PAGE_SIZE), accessTokenRepository.count());

    context.useBearerAdminToken();
    /* get first page */
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertEquals(Long.valueOf(MAX_PAGE_SIZE), atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(MAX_PAGE_SIZE, atl.getItemsPerPage());
    assertEquals(MAX_PAGE_SIZE, atl.getResources().size());
  }

  @Test
  void getAccessTokenListLimitedToPageSizeSecondPage() throws Exception {

    context.useLocalTestUser();
    for (int i = 0; i < MAX_PAGE_SIZE; i++) {
      getPasswordToken(DEFAULT_SCOPES);
    }

    assertEquals(Long.valueOf(MAX_PAGE_SIZE), accessTokenRepository.count());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().startIndex(MAX_PAGE_SIZE).build();

    context.useBearerAdminToken();
    /* get second page */
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(Long.valueOf(MAX_PAGE_SIZE), atl.getTotalResults());
    assertEquals(MAX_PAGE_SIZE, atl.getStartIndex());
    assertEquals(1, atl.getItemsPerPage());
    assertEquals(1, atl.getResources().size());
  }

  @Test
  void getAccessTokenListFilterUserIdInjection() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);

    assertEquals(1L, accessTokenRepository.count());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(INJECTION_QUERY).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(0L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
    assertEquals(0, atl.getResources().size());
  }

  @Test
  void getAccessTokenListWithOneClientCredentialAccessToken() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertEquals(2L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(2, atl.getItemsPerPage());
  }

  @Test
  void getAllValidAccessTokensCountWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    clock.advance(Duration.ofHours(6));
    getPasswordToken(DEFAULT_SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
  }

  @Test
  void getAllValidAccessTokensCountForUserWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES).accessToken();
    clock.advance(Duration.ofDays(1));
    getPasswordToken(DEFAULT_SCOPES).accessToken();
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertEquals(3L, accessTokenRepository.count());

    Page<OAuth2AccessTokenEntity> tokens =
        accessTokenRepository.findAllValidAccessTokens(clock.now(), FIRST_10);
    assertEquals(2L, tokens.getTotalElements());

    tokens =
        accessTokenRepository.findValidAccessTokensForUser(TEST_USERNAME, clock.now(), FIRST_10);
    assertEquals(1L, tokens.getTotalElements());
    tokens =
        accessTokenRepository.findValidAccessTokensForUser(ADMIN_USERNAME, clock.now(), FIRST_10);
    assertEquals(1L, tokens.getTotalElements());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).userId(TEST_USERNAME).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
  }

  @Test
  void getAllValidAccessTokensCountForClientWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    clock.advance(Duration.ofHours(6));
    getPasswordToken(DEFAULT_SCOPES);

    assertEquals(2L, accessTokenRepository.count());

    Page<OAuth2AccessTokenEntity> tokens =
        accessTokenRepository.findAllValidAccessTokens(clock.now(), FIRST_10);
    assertEquals(1L, tokens.getTotalElements());

    tokens = accessTokenRepository.findValidAccessTokensForClient(PASSWORD_CLIENT_ID, clock.now(),
        FIRST_10);
    assertEquals(1L, tokens.getTotalElements());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
  }

  @Test
  void getAllValidAccessTokensCountForUserAndClientWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);
    clock.advance(Duration.ofDays(1));
    context.useLocalTestUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME, TEST_PASSWORD,
        DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);

    assertEquals(6L, accessTokenRepository.count());

    Page<OAuth2AccessTokenEntity> tokens =
        accessTokenRepository.findAllValidAccessTokens(clock.now(), FIRST_10);
    assertEquals(3L, tokens.getTotalElements());

    tokens = accessTokenRepository.findValidAccessTokensForUserAndClient(TEST_USERNAME,
        PASSWORD_CLIENT_ID, clock.now(), FIRST_10);
    assertEquals(1L, tokens.getTotalElements());

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder()
      .count(0)
      .userId(TEST_USERNAME)
      .clientId(PASSWORD_CLIENT_ID)
      .build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(0, atl.getItemsPerPage());
  }

  @Test
  void getAccessTokenListAfterClearingPersistenceContext() throws Exception {

    context.useLocalTestUser();
    String jwt = getPasswordToken(DEFAULT_SCOPES).accessToken();
    Set<String> expectedAudiences =
        new HashSet<>(SignedJWT.parse(jwt).getJWTClaimsSet().getAudience());
    org.junit.jupiter.api.Assertions.assertFalse(expectedAudiences.isEmpty());
    entityManager.flush();
    entityManager.clear();

    OAuth2AccessTokenEntity reloaded = accessTokenRepository.findAll().get(0);
    assertNull(reloaded.getJwt());
    assertEquals(expectedAudiences, reloaded.getAudiences());

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> result = getAccessTokenList();
    assertEquals(1, result.getResources().size());
    assertEquals(expectedAudiences, result.getResources().get(0).audiences());
  }
}
