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
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.persistence.model.IamAccount;
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@DirtiesContext(classMode = AFTER_EACH_TEST_METHOD)
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class GetRevokeRefreshTokenTests extends TokensUtils {

  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;

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
  public void getRefreshToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2RefreshTokenEntity rt = buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, rt.getId());

    RefreshToken remoteRt = mapper.readValue(
        mvc.perform(get(path).contentType(CONTENT_TYPE))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString(),
        RefreshToken.class);

    System.out.println(remoteRt);

    assertThat(remoteRt.getId(), equalTo(rt.getId()));
    assertThat(remoteRt.getValue(), equalTo(rt.getValue()));
    assertThat(remoteRt.getExpiration(), equalTo(rt.getExpiration()));

    assertThat(remoteRt.getScopes().contains("openid"), equalTo(true));
    assertThat(remoteRt.getScopes().contains("profile"), equalTo(true));
    assertThat(remoteRt.getScopes().contains("offline_access"), equalTo(true));

    assertThat(remoteRt.getClient().getId(), equalTo(client.getId()));
    assertThat(remoteRt.getClient().getClientId(), equalTo(client.getClientId()));

    assertThat(remoteRt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteRt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteRt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  public void getRefreshTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(get(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());
  }

  @Test
  public void revokeRefreshToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    OAuth2RefreshTokenEntity rt = buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, rt.getId());

    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isNoContent());
    mvc.perform(get(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());

    assertThat(tokenService.getRefreshTokenById(rt.getId()), equalTo(null));
  }

  @Test
  public void revokeAccessTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());
  }
}
