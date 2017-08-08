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
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.TokensListResponse;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
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
public class GetAccessTokenListTests extends TokensUtils {

  public static final String[] SCOPES = {"openid", "profile"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamOAuthAccessTokenRepository tokenRepository;

  private static final String TESTUSER_USERNAME = "test_102";
  private static final String TESTUSER2_USERNAME = "test_103";
  private static final String PARTIAL_USERNAME = "test_10";

  @Before
  public void setup() {
    initMvc();
  }

  @After
  public void teardown() {
    clearAllTokens();
  }

  @Test
  public void getEmptyAccessTokenList() throws Exception {

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(0)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
  }

  @Test
  public void getNotEmptyAccessTokenListWithCountZero() throws Exception {

    buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE).param("count", "0"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
  }

  @Test
  public void getAccessTokenListWithAttributes() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2AccessTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE).param("attributes",
            "user,idToken"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(2)));
    assertThat(atl.getResources().size(), equalTo(2));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.stream().filter(a -> a.getIdToken() != null).findFirst().get();

    assertThat(remoteAt.getId(), equalTo(at.getId()));
    assertThat(remoteAt.getClient(), equalTo(null));
    assertThat(remoteAt.getExpiration(), equalTo(null));
    assertThat(remoteAt.getIdToken().getId(), equalTo(at.getIdToken().getId()));
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

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE).param("clientId",
            client1.getClientId()))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(2)));
    assertThat(atl.getResources().size(), equalTo(2));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.stream().filter(a -> a.getIdToken() != null).findFirst().get();

    assertThat(remoteAt.getId(), equalTo(target.getId()));
    assertThat(remoteAt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteAt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteAt.getExpiration(), equalTo(target.getExpiration()));
    assertThat(remoteAt.getIdToken().getId(), equalTo(target.getIdToken().getId()));
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

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE).param("userId",
            user1.getUsername()))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(2)));
    assertThat(atl.getResources().size(), equalTo(2));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.stream().filter(a -> a.getIdToken() != null).findFirst().get();

    assertThat(remoteAt.getId(), equalTo(target.getId()));
    assertThat(remoteAt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteAt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteAt.getExpiration(), equalTo(target.getExpiration()));
    assertThat(remoteAt.getIdToken().getId(), equalTo(target.getIdToken().getId()));
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

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("userId", user1.getUsername())
            .param("clientId", client1.getClientId()))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(2)));
    assertThat(atl.getResources().size(), equalTo(2));

    List<AccessToken> acl = atl.getResources();
    AccessToken remoteAt = acl.stream().filter(a -> a.getIdToken() != null).findFirst().get();

    assertThat(remoteAt.getId(), equalTo(target.getId()));
    assertThat(remoteAt.getClient().getId(), equalTo(target.getClient().getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(target.getClient().getClientId()));
    assertThat(remoteAt.getClient().getRef(), equalTo(target.getClient().getClientUri()));

    assertThat(remoteAt.getExpiration(), equalTo(target.getExpiration()));
    assertThat(remoteAt.getIdToken().getId(), equalTo(target.getIdToken().getId()));
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

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("userId", PARTIAL_USERNAME))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(0)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
    assertThat(atl.getResources().size(), equalTo(0));
  }

  @Test
  public void getAccessTokenListLimitedToPageSize() throws Exception {

    for (int i = 0; i < TOKENS_MAX_PAGE_SIZE; i++) {
      buildAccessToken(loadTestClient(TEST_CLIENT_ID), TESTUSER_USERNAME, SCOPES);
    }

    /* get first page */
    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2*TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));

    /* get second page */
    atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("startIndex", String.valueOf(TOKENS_MAX_PAGE_SIZE)))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(2*TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(TOKENS_MAX_PAGE_SIZE)));
    assertThat(atl.getResources().size(), equalTo(TOKENS_MAX_PAGE_SIZE));
  }

  @Test
  public void getAccessTokenListFilterUserIdInjection() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    assertThat(tokenRepository.countAllTokens(), equalTo(2));

    TokensListResponse<AccessToken> atl = mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)
            .param("userId", "1%; DELETE FROM access_token; SELECT * FROM access_token WHERE userId LIKE %"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        new TypeReference<TokensListResponse<AccessToken>>() {});

    assertThat(atl.getTotalResults(), equalTo(Long.valueOf(0)));
    assertThat(atl.getStartIndex(), equalTo(Long.valueOf(1)));
    assertThat(atl.getItemsPerPage(), equalTo(Long.valueOf(0)));
    assertThat(atl.getResources().size(), equalTo(0));

    assertThat(tokenRepository.countAllTokens(), equalTo(2));
  }
}
