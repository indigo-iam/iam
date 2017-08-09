package it.infn.mw.iam.test.api.tokens;

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.CONTENT_TYPE;
import static it.infn.mw.iam.api.tokens.TokensControllerSupport.TOKENS_MAX_PAGE_SIZE;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.google.common.collect.Lists;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.model.TokensListResponse;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.util.List;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@DirtiesContext(classMode = AFTER_EACH_TEST_METHOD)
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class GetRefreshTokenListTests extends TokensUtils {

  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamOAuthRefreshTokenRepository tokenRepository;

  private static final String TESTUSER_USERNAME = "test_102";
  private static final String TESTUSER2_USERNAME = "test_103";

  @Before
  public void setup() {
    initMvc();
  }

  @After
  public void teardown() {
    clearAllTokens();
  }

  @Test
  public void getEmptyRefreshTokenList() throws Exception {

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(0)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
  }

  @Test
  public void getNotEmptyRefreshTokenListWithCountZero() throws Exception {

    buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE).param("count", "0"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(1)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
  }

  @Test
  public void getRefreshTokenListWithAttributes() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2RefreshTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE).param("attributes", "user,idToken"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(1)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(1)));
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
    OAuth2RefreshTokenEntity target = buildAccessToken(client1, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    refreshTokens.add(target);
    refreshTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES).getRefreshToken());

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("clientId", client1.getClientId()))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(1)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(1)));
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
    OAuth2RefreshTokenEntity target = buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    refreshTokens.add(target);
    refreshTokens.add(buildAccessToken(client, TESTUSER2_USERNAME, SCOPES).getRefreshToken());

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("userId", user1.getUsername()))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(1)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(1)));
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
    OAuth2RefreshTokenEntity target = buildAccessToken(client1, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    refreshTokens.add(target);
    refreshTokens.add(buildAccessToken(client1, TESTUSER2_USERNAME, SCOPES).getRefreshToken());
    refreshTokens.add(buildAccessToken(client2, TESTUSER_USERNAME, SCOPES).getRefreshToken());
    refreshTokens.add(buildAccessToken(client2, TESTUSER2_USERNAME, SCOPES).getRefreshToken());

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("userId", user1.getUsername())
            .param("clientId", client1.getClientId()))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(1)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(1)));
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
  public void getRefreshTokenListLimitedToPageSize() throws Exception {

    for (int i = 0; i < 2*TOKENS_MAX_PAGE_SIZE; i++) {
      buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    }

    /* get first page */
    TokensListResponse<RefreshToken> rtl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(rtl.getTotalResults(), equalTo(Long.valueOf(2*TOKENS_MAX_PAGE_SIZE)));
    assertThat(rtl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(rtl.getItemsPerPage(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(rtl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));

    /* get second page */
    rtl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("startIndex", String.valueOf(TOKENS_MAX_PAGE_SIZE)))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(rtl.getTotalResults(), equalTo(Long.valueOf(2*TOKENS_MAX_PAGE_SIZE)));
    assertThat(rtl.getStartIndex(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(rtl.getItemsPerPage(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(rtl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));
  }

  @Test
  public void getRefreshTokenListFilterUserIdInjection() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.countAllTokens(), equalTo(1));

    TokensListResponse<RefreshToken> atl = mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("userId", "1%; DELETE FROM access_token; SELECT * FROM refresh_token WHERE userId LIKE %"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<RefreshToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(0)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
    assertThat(atl.getResources().size(), equalTo(0));

    assertThat(tokenRepository.countAllTokens(), equalTo(1));
  }
}
