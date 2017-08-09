package it.infn.mw.iam.test.api.tokens;

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.CONTENT_TYPE;
import static org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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
public class AccessTokenPermissionsTests extends TokensUtils {

  private static final String TESTUSER_USERNAME = "test_102";
  private static final int FAKE_TOKEN_ID = 12345;

  @Before
  public void setup() {
    initMvc();
  }


  @Test
  public void getAccessTokenListAsAnonymous() throws Exception {
    mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)).andExpect(status().isUnauthorized());
  }

  @Test
  public void revokeAccessTokenAsAnonymous() throws Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, authorities = {"ROLE_USER"})
  public void getAccessTokenListAsAuthenticatedUser() throws Exception {

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, authorities = {"ROLE_USER"})
  public void revokeAccessTokenAsAuthenticatedUser() throws Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, authorities = {"ROLE_ADMIN"})
  public void getAccessTokenListAsAdmin() throws Exception {

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH).contentType(CONTENT_TYPE)).andExpect(status().isOk());
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, authorities = {"ROLE_ADMIN"})
  public void revokeAccessTokenAsAdmin() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(CONTENT_TYPE)).andExpect(status().isNotFound());
  }
}
