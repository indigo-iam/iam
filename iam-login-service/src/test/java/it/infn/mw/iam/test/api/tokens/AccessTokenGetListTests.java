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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
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

    assertThat(accessTokenRepository.count(), equalTo(0L));

    /* get list */
    context.useBearerAdminToken();
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
  void getNotEmptyAccessTokenListWithCountZero() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().count(0).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(accessTokenRepository.count(), equalTo(1L));
    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  void getAccessTokenListWithClientIdFilter() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    getPasswordToken(DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);

    assertThat(accessTokenRepository.count(), equalTo(3L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
    assertThat(atl.getResources().size(), equalTo(2));

    atl.getResources().forEach(at -> assertThat(at.clientId(), equalTo(PASSWORD_CLIENT_ID)));
  }

  @Test
  void getAccessTokenListWithUserIdFilter() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES).accessToken();
    getPasswordToken(DEFAULT_SCOPES).accessToken();
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertThat(accessTokenRepository.count(), equalTo(3L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
    assertThat(atl.getResources().size(), equalTo(2));

    atl.getResources().forEach(at -> {
      assertThat(at.user().username(), equalTo(TEST_USERNAME));
      assertThat(at.user().ref(), equalTo(scimResourceLocationProvider.userLocation(TEST_UUID)));
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

    assertThat(accessTokenRepository.count(), equalTo(3L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(TEST_USERNAME).clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));

    atl.getResources().forEach(at -> {
      assertThat(at.clientId(), equalTo(PASSWORD_CLIENT_ID));
      assertThat(at.user().username(), equalTo(TEST_USERNAME));
      assertThat(at.user().ref(), equalTo(scimResourceLocationProvider.userLocation(TEST_UUID)));
    });
  }

  @Test
  void getAccessTokenListWithPartialUserIdFilterReturnsEmpty() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useLocalAdminUser();
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
        DEFAULT_SCOPES);

    assertThat(accessTokenRepository.count(), equalTo(2L));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder().userId("tes").build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  void getAccessTokenListLimitedToPageSizeFirstPage() throws Exception {

    context.useLocalTestUser();
    for (int i = 0; i < MAX_PAGE_SIZE; i++) {
      getPasswordToken(DEFAULT_SCOPES);
    }

    assertThat(accessTokenRepository.count(), equalTo(Long.valueOf(MAX_PAGE_SIZE)));

    context.useBearerAdminToken();
    /* get first page */
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(MAX_PAGE_SIZE));
    assertThat(atl.getResources().size(), equalTo(MAX_PAGE_SIZE));
  }

  @Test
  void getAccessTokenListLimitedToPageSizeSecondPage() throws Exception {

    context.useLocalTestUser();
    for (int i = 0; i < MAX_PAGE_SIZE; i++) {
      getPasswordToken(DEFAULT_SCOPES);
    }

    assertThat(accessTokenRepository.count(), equalTo(Long.valueOf(MAX_PAGE_SIZE)));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().startIndex(MAX_PAGE_SIZE).build();

    context.useBearerAdminToken();
    /* get second page */
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(MAX_PAGE_SIZE));
    assertThat(atl.getItemsPerPage(), equalTo(1));
    assertThat(atl.getResources().size(), equalTo(1));
  }

  @Test
  void getAccessTokenListFilterUserIdInjection() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);

    assertThat(accessTokenRepository.count(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().userId(INJECTION_QUERY).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(0L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  void getAccessTokenListWithOneClientCredentialAccessToken() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    context.useBearerClientToken();
    getClientCredentialsToken(DEFAULT_SCOPES);

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList();

    assertThat(atl.getTotalResults(), equalTo(2L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(2));
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

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
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

    assertThat(accessTokenRepository.count(), equalTo(3L));

    Page<OAuth2AccessTokenEntity> tokens =
        accessTokenRepository.findAllValidAccessTokens(clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(2L));

    tokens =
        accessTokenRepository.findValidAccessTokensForUser(TEST_USERNAME, clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));
    tokens =
        accessTokenRepository.findValidAccessTokensForUser(ADMIN_USERNAME, clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).userId(TEST_USERNAME).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }

  @Test
  void getAllValidAccessTokensCountForClientWithExpiredTokens() throws Exception {

    context.useLocalTestUser();
    getPasswordToken(DEFAULT_SCOPES);
    clock.advance(Duration.ofHours(6));
    getPasswordToken(DEFAULT_SCOPES);

    assertThat(accessTokenRepository.count(), equalTo(2L));

    Page<OAuth2AccessTokenEntity> tokens =
        accessTokenRepository.findAllValidAccessTokens(clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    tokens = accessTokenRepository.findValidAccessTokensForClient(PASSWORD_CLIENT_ID, clock.now(),
        FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params =
        MultiValueMapBuilder.builder().count(0).clientId(PASSWORD_CLIENT_ID).build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
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

    assertThat(accessTokenRepository.count(), equalTo(6L));

    Page<OAuth2AccessTokenEntity> tokens =
        accessTokenRepository.findAllValidAccessTokens(clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(3L));

    tokens = accessTokenRepository.findValidAccessTokensForUserAndClient(TEST_USERNAME,
        PASSWORD_CLIENT_ID, clock.now(), FIRST_10);
    assertThat(tokens.getTotalElements(), equalTo(1L));

    MultiValueMap<String, String> params = MultiValueMapBuilder.builder()
      .count(0)
      .userId(TEST_USERNAME)
      .clientId(PASSWORD_CLIENT_ID)
      .build();

    context.useBearerAdminToken();
    ListResponseDTO<AccessToken> atl = getAccessTokenList(params);

    assertThat(atl.getTotalResults(), equalTo(1L));
    assertThat(atl.getStartIndex(), equalTo(1));
    assertThat(atl.getItemsPerPage(), equalTo(0));
  }
}
