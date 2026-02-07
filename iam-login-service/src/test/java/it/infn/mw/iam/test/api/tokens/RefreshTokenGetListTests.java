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
import static it.infn.mw.iam.api.tokens.TokensControllerSupport.TOKENS_MAX_PAGE_SIZE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=true",
    "iam.access_token.store_on_database=true"})
@Transactional
class RefreshTokenGetListTests extends TokenGetterUtils {

  static final String[] SCOPES = {"openid", "profile", "offline_access"};

  static final int FAKE_TOKEN_ID = 12345;

  static final String INJECTION_QUERY =
      "1%; DELETE FROM access_token; SELECT * FROM refresh_token WHERE userId LIKE %";

  static final Pageable FIRST_10 = new OffsetPageable(0, 10);
  static final String DEFAULT_SCOPES = "openid offline_access";

  @Autowired
  ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  @BeforeEach
  void initSecurityContext() {
    context.cleanupSecurityContext();
    refreshTokenRepository.deleteAll();
    assertEquals(0L, refreshTokenRepository.count());
  }

  @Test
  void forbiddenRefreshTokenList() throws Exception {

    /* get list */
    context.useBearerTestToken(new String[] {"openid", "profile"});
    mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isForbidden());
  }

  @Test
  void getEmptyRefreshTokenList() throws Exception {

    /* get list */
    context.useBearerAdminToken();
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
  void getNotEmptyRefreshTokenListWithCountZero() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(refreshTokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  void getRefreshTokenListWithAttributes() throws Exception {

    context.useLocalTestUser();
    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().attributes("user,expiration").build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertEquals(1L, refreshTokenRepository.count());
    assertEquals(1L, atl.getTotalResults());
    assertEquals(1, atl.getStartIndex());
    assertEquals(1, atl.getItemsPerPage());
    assertEquals(1, atl.getResources().size());

    RefreshToken remoteRt = atl.getResources().get(0);

    assertNull(remoteRt.getClient());
    assertNotNull(remoteRt.getExpiration());
    assertNotNull(remoteRt.getUser());
    assertEquals(TEST_USERNAME, remoteRt.getUser().getUserName());
    assertEquals(scimResourceLocationProvider.userLocation(TEST_UUID), remoteRt.getUser().getRef());
  }

  @Test
  void getRefreshTokenListWithClientIdFilter() throws Exception {

    context.useLocalTestUser();
    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());
    context.useLocalTestUser();
    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());
    context.useAnotherLocalUser(TEST_CLIENT_ID);
    assertNotNull(getPasswordToken(TEST_CLIENT_ID, TEST_CLIENT_SECRET, ANOTHER_USERNAME,
        ANOTHER_PASSWORD, DEFAULT_SCOPES).refreshToken());

    assertThat(refreshTokenRepository.count(), equalTo(3L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
    assertThat(atl.getResources().size(), equalTo(2));

    atl.getResources()
      .forEach(rt -> assertThat(rt.getClient().getClientId(), equalTo(PASSWORD_CLIENT_ID)));
  }

  @Test
  void getRefreshTokenListWithUserIdFilter() throws Exception {

    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());
    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());
    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME,
        ADMIN_PASSWORD, DEFAULT_SCOPES));

    assertThat(refreshTokenRepository.count(), equalTo(3L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
    assertThat(atl.getResources().size(), equalTo(2));

    atl.getResources().forEach(at -> {
      assertThat(at.getUser().getUserName(), equalTo(TEST_USERNAME));
      assertThat(at.getUser().getRef(),
          equalTo(scimResourceLocationProvider.userLocation(TEST_UUID)));
    });
  }

  @Test
  void getRefreshTokenListWithClientIdAndUserIdFilter() throws Exception {

    context.useLocalTestUser(TEST_CLIENT_ID);
    getPasswordToken(TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_USERNAME, TEST_PASSWORD,
        DEFAULT_SCOPES);
    context.useLocalAdminUser(PASSWORD_CLIENT_ID);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertThat(refreshTokenRepository.count(), equalTo(2L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));

    context.useLocalTestUser(PASSWORD_CLIENT_ID);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME, TEST_PASSWORD,
        DEFAULT_SCOPES);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME, TEST_PASSWORD,
        DEFAULT_SCOPES);

    context.useBearerAdminToken();
    atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
    assertThat(atl.getResources().size(), equalTo(2));

    atl.getResources().forEach(at -> {
      assertThat(at.getClient().getClientId(), equalTo(PASSWORD_CLIENT_ID));
      assertThat(at.getUser().getUserName(), equalTo(TEST_USERNAME));
      assertThat(at.getUser().getRef(),
          equalTo(scimResourceLocationProvider.userLocation(TEST_UUID)));
    });
  }

  @Test
  void getRefreshTokenListWithPartialUserIdFilterReturnsEmpty() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertThat(refreshTokenRepository.count(), equalTo(2L));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().userId("tes").build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  void getRefreshTokenListLimitedToPageSizeFirstPage() throws Exception {

    context.useLocalTestUser();
    for (int i = 0; i < TOKENS_MAX_PAGE_SIZE; i++) {
      getPasswordToken(DEFAULT_SCOPES);
    }

    assertThat(refreshTokenRepository.count(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));

    context.useBearerAdminToken();
    /* get first page */
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList();

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));
  }

  @Test
  void getRefreshTokenListLimitedToPageSizeSecondPage() throws Exception {

    context.useLocalTestUser();
    for (int i = 0; i < TOKENS_MAX_PAGE_SIZE; i++) {
      getPasswordToken(DEFAULT_SCOPES);
    }

    assertThat(refreshTokenRepository.count(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().startIndex(TOKENS_MAX_PAGE_SIZE).build();

    context.useBearerAdminToken();
    /* get second page */
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(TOKENS_MAX_PAGE_SIZE));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));
  }

  @Test
  void getRefreshTokenListFilterUserIdInjection() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);

    assertThat(refreshTokenRepository.count(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(INJECTION_QUERY).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  void getAllValidRefreshTokensCountWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    clock.advance(Duration.ofHours(40));
    getPasswordToken(DEFAULT_SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
  }

  @Test
  void getAllValidRefreshTokensCountForUserWithExpiredTokens() throws Exception {

    context.useLocalTestUser();

    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());

    clock.advance(Duration.ofDays(40));

    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, DEFAULT_SCOPES).refreshToken());

    context.useLocalAdminUser();

    assertNotNull(getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME,
        ADMIN_PASSWORD, DEFAULT_SCOPES).refreshToken());

    assertThat(refreshTokenRepository.count(), equalTo(3L));

    Page<OAuth2RefreshTokenEntity> tokens =
        refreshTokenRepository.findAllValidRefreshTokens(clock.now(), FIRST_10);
    assertEquals(2L, tokens.getTotalElements());

    tokens =
        refreshTokenRepository.findValidRefreshTokensForUser(TEST_USERNAME, clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));
    tokens =
        refreshTokenRepository.findValidRefreshTokensForUser(ADMIN_USERNAME, clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
  }

  @Test
  void getAllValidRefreshTokensCountForClientWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    clock.advance(Duration.ofDays(2));
    getPasswordToken(DEFAULT_SCOPES);

    assertThat(refreshTokenRepository.count(), equalTo(2L));

    Page<OAuth2RefreshTokenEntity> tokens =
        refreshTokenRepository.findAllValidRefreshTokens(clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    tokens = refreshTokenRepository.findValidRefreshTokensForClient(PASSWORD_CLIENT_ID, clock.now(),
        FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
  }


  @Test
  void getAllValidRefreshTokensCountForUserAndClientWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);
    clock.advance(Duration.ofDays(40));
    context.useLocalTestUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME, TEST_PASSWORD,
        DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertThat(refreshTokenRepository.count(), equalTo(4L));

    Page<OAuth2RefreshTokenEntity> tokens =
        refreshTokenRepository.findAllValidRefreshTokens(clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(2L));

    tokens = refreshTokenRepository.findValidRefreshTokensForUserAndClient(TEST_USERNAME,
        PASSWORD_CLIENT_ID, clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<RefreshToken> atl = getRefreshTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
  }
}
