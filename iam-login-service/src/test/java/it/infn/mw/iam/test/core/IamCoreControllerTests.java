package it.infn.mw.iam.test.core;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.WithMockOIDCUser;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
public class IamCoreControllerTests {

  @Autowired
  protected WebApplicationContext context;

  protected MockMvc mvc;

  @Value("${iam.baseUrl}")
  String iamBaseUrl;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(print())
      .build();
  }



  @Test
  public void registerRedirectsToRegisterPage() throws Exception {
    mvc.perform(get("/register")).andExpect(status().isOk()).andExpect(view().name("iam/register"));

  }

  @Test
  public void unauthenticatedUserIsRedirectedToLoginPage() throws Exception {

    // Here the spring security filter assumes we run on localhost:80
    mvc.perform(get("/")).andDo(print()).andExpect(status().isFound()).andExpect(
        redirectedUrl("http://localhost/login"));

    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"));

  }

  @Test
  public void anonymousIsAcceptedAtLoginPage() throws Exception {

    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"));

  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void authenticatedUserIsRedirectedToRoot() throws Exception {

    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/"));
  }

  @Test
  @WithMockOIDCUser
  public void externallyAuthenticatedUserIsRedirectedToRegisterPage() throws Exception {
    mvc.perform(get("/login"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("iam/register"));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void resetSessionClearsSecurityContext() throws Exception {
    mvc.perform(get("/reset-session"))
      .andDo(print())
      .andExpect(status().isFound())
      .andExpect(unauthenticated());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void authenticatedAccessToRootLeadsToMitreWebapp() throws Exception {
    mvc.perform(get("/")).andDo(print()).andExpect(status().isOk()).andExpect(view().name("home"));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void authenticatedAccessToManageLeadsToMitreManageWebapp() throws Exception {
    mvc.perform(get("/manage"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(view().name("manage"));
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred", scopes = {"openid"})
  public void userinfoDeniesAccessForClientCredentialsClient() throws Exception {

    mvc.perform(get("/userinfo")).andDo(print()).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(scopes = {"openid"}, user = "not-found", authorities = {"ROLE_USER"})
  public void userinfoReturns404ForUserNotFound() throws Exception {

    mvc.perform(get("/userinfo")).andDo(print()).andExpect(status().isNotFound());
  }


  @Test
  @WithMockOAuthUser(scopes = {"openid", "profile", "email"}, user = "test",
      authorities = {"ROLE_USER"}, externallyAuthenticated = true,
      externalAuthenticationType = ExternalAuthenticationType.OIDC)
  public void userInfoReturnsExternalAuthenticationInfo() throws Exception {

    mvc.perform(get("/userinfo")).andDo(print()).andExpect(status().isOk()).andExpect(
        jsonPath("$.external_authn.type", equalTo("oidc")));
  }

  @Test
  @WithMockOAuthUser(scopes = {"openid profile"}, user = "test", authorities = {"ROLE_USER"})
  public void userinfoWithClaims() throws Exception {

    String userInfoClaimsRequest = "{ \"userinfo\" : { \"groups\": null }}";

    mvc.perform(get("/userinfo").param("claims", userInfoClaimsRequest))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.groups", hasSize(2)));
  }

  @Test
  public void testWebfingerUserFound() throws Exception {
    mvc.perform(get("/.well-known/webfinger").param("resource", "acct:test@iam.test").param("rel",
        "http://openid.net/specs/connect/1.0/issuer"))
      .andExpect(status().isOk());

  }

  @Test
  public void testWebfingerUserNotFound() throws Exception {
    mvc
      .perform(get("/.well-known/webfinger").param("resource", "acct:not-found@example.org")
        .param("rel", "http://openid.net/specs/connect/1.0/issuer"))
      .andExpect(status().isNotFound());

  }

  @Test
  public void testUnknownUriFormat() throws Exception {
    mvc.perform(get("/.well-known/webfinger").param("resource", "xyz://not.supported").param("rel",
        "http://openid.net/specs/connect/1.0/issuer"))
      .andExpect(status().isNotFound());

  }

  @Test
  public void testWebfingerNonOidcRel() throws Exception {
    mvc.perform(get("/.well-known/webfinger").param("resource", "acct:not-found@example.org")
      .param("rel", "another.rel")).andExpect(status().isNotFound());

  }
}
