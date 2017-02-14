package it.infn.mw.iam.test.oauth;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;

import javax.transaction.Transactional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.oidc.TokenResponse;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebAppConfiguration
@Transactional
public class OpenIDConnectAudienceTests {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";

  public static final String RESPONSE_TYPE_CODE = "code";
  public static final String AUTHORIZATION_ENDPOINT = "/authorize";
  public static final String SCOPE = "openid profile";

  public static final String TEST_USER_ID = "test";
  public static final String TEST_USER_PASSWORD = "password";

  @Autowired
  WebApplicationContext context;

  @Autowired
  ObjectMapper objectMapper;

  MockMvc mvc;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(print())
      .build();
  }


  @Test
  public void testOidcAuthorizationRequestWithAudience() throws Exception {

    User testUser = new User(TEST_USER_ID, TEST_USER_PASSWORD,
        commaSeparatedStringToAuthorityList("ROLE_USER"));

    MockHttpSession session = (MockHttpSession) mvc
      .perform(get(AUTHORIZATION_ENDPOINT).param("response_type", RESPONSE_TYPE_CODE)
        .param("client_id", TEST_CLIENT_ID)
        .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .param("scope", SCOPE)
        .param("nonce", "1")
        .param("state", "1")
        .param("aud", "example-audience")
        .with(SecurityMockMvcRequestPostProcessors.user(testUser)))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/oauth/confirm_access"))
      .andReturn()
      .getRequest()
      .getSession();

    MvcResult result = mvc
      .perform(post("/authorize").session(session)
        .param("user_oauth_approval", "true")
        .param("scope_openid", "openid")
        .param("scope_profile", "profile")
        .param("authorize", "Authorize")
        .param("remember", "none")
        .with(csrf()))
      .andExpect(status().is3xxRedirection())
      .andReturn();

    String redirectUrl = result.getResponse().getRedirectedUrl();
    session = (MockHttpSession) result.getRequest().getSession();

    assertThat(redirectUrl, startsWith(TEST_CLIENT_REDIRECT_URI));
    UriComponents redirectUri = UriComponentsBuilder.fromUri(new URI(redirectUrl)).build();
    String code = redirectUri.getQueryParams().getFirst("code");

    String tokenResponse = mvc
      .perform(post("/token").param("grant_type", "authorization_code")
        .param("code", code)
        .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .with(SecurityMockMvcRequestPostProcessors.httpBasic(TEST_CLIENT_ID, TEST_CLIENT_SECRET)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    TokenResponse response = objectMapper.readValue(tokenResponse, TokenResponse.class);

    response.getAccessToken();

    JWT token = JWTParser.parse(response.getAccessToken());
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), contains("example-audience"));

    JWT idToken = JWTParser.parse(response.getIdToken());

    JWTClaimsSet idTokenClaims = idToken.getJWTClaimsSet();
    assertNotNull(idTokenClaims.getAudience());
    assertThat(idTokenClaims.getAudience().size(), equalTo(1));
    assertThat(idTokenClaims.getAudience(), contains(TEST_CLIENT_ID));

  }
}
