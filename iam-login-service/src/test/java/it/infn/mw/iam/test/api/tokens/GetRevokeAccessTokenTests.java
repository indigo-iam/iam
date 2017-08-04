package it.infn.mw.iam.test.api.tokens;

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.CONTENT_TYPE;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.TokensResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.persistence.model.IamAccount;
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@DirtiesContext(classMode = AFTER_EACH_TEST_METHOD)
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class GetRevokeAccessTokenTests extends TokensUtils {

  public static final String[] SCOPES = {"openid", "profile"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;

  @Autowired
  private TokensResourceLocationProvider tokensResourceLocationProvider;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private ObjectMapper mapper;

  private static final String TESTUSER_USERNAME = "test_102";

  @Before
  public void setup() {
    initMvc();
  }

  @After
  public void teardown() {
    clearAllTokens();
  }

  @Test
  public void getAccessToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2AccessTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, at.getId());

    AccessToken remoteAt = mapper.readValue(
        mvc.perform(get(path).contentType(CONTENT_TYPE))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        AccessToken.class);

    System.out.println(remoteAt);

    assertThat(remoteAt.getId(), equalTo(at.getId()));
    assertThat(remoteAt.getValue(), equalTo(at.getValue()));
    assertThat(remoteAt.getExpiration(), equalTo(at.getExpiration()));

    assertThat(remoteAt.getScopes().contains("openid"), equalTo(true));
    assertThat(remoteAt.getScopes().contains("profile"), equalTo(true));

    assertThat(remoteAt.getIdToken().getId(), equalTo(at.getIdToken().getId()));
    assertThat(remoteAt.getIdToken().getRef(),
        equalTo(tokensResourceLocationProvider.accessTokenLocation(at.getIdToken().getId())));

    assertThat(remoteAt.getClient().getId(), equalTo(client.getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(client.getClientId()));

    assertThat(remoteAt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteAt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteAt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  public void getAccessTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(get(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());
  }

  @Test
  public void revokeAccessToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    OAuth2AccessTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, at.getId());

    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isNoContent());
    mvc.perform(get(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());

    assertThat(tokenService.getAccessTokenById(at.getId()), equalTo(null));
  }

  @Test
  public void revokeAccessTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());
  }
}
