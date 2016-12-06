package it.infn.mw.iam.test.ext_authn.account_linking;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.transaction.Transactional;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ext_authn.saml.SamlExternalAuthenticationTestSupport;
import it.infn.mw.iam.test.ext_authn.saml.SamlTestConfig;
import it.infn.mw.iam.test.util.saml.SamlUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, SamlTestConfig.class})
@WebAppConfiguration
@Transactional
public class SamlAccountLinkingTests extends SamlExternalAuthenticationTestSupport {

  private static final String TEST_100_USER = "test_100";

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void samlAccountLinkingWorks() throws Throwable {

    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andDo(MockMvcResultHandlers.print())
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest1Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isOk())
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, nullValue()))
      .andExpect(forwardedUrl("/iam/account-linking/SAML/done"))
      .andExpect(authenticated().withUsername(TEST_100_USER))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get("/iam/account-linking/SAML/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()));

    IamAccount account = iamAccountRepo.findBySamlId(DEFAULT_IDP_ID, T1_EPUID)
      .orElseThrow(() -> new AssertionError("User not found linked to expected SAML id"));

    Assert.assertThat(account.getUsername(), equalTo(TEST_100_USER));

    // Cleanup!
    account.getSamlIds().stream().forEach(i -> i.setAccount(null));
    account.getSamlIds().clear();
    iamAccountRepo.save(account);
  }


  @Test
  @WithMockUser(username = TEST_100_USER)
  public void samlAccountLinkingFailsSinceSamlAccountAlreadyLinkedToAnotherUser() throws Throwable {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest2Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isOk())
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, nullValue()))
      .andExpect(forwardedUrl("/iam/account-linking/SAML/done"))
      .andExpect(authenticated().withUsername(TEST_100_USER))
      .andReturn()
      .getRequest()
      .getSession();

    String expectedErrorMessage = String
      .format("SAML account '[%s] %s' is already linked to another user", DEFAULT_IDP_ID, T2_EPUID);

    mvc.perform(get("/iam/account-linking/SAML/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, equalTo(expectedErrorMessage)));


  }

  @Test
  @WithMockUser(username = "test")
  public void samlAccountLinkingFailsSinceSamlAccountIsAlreadyBoundToAuthenticatedUser()
      throws Throwable {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildTest2Response(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(status().isOk())
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, nullValue()))
      .andExpect(forwardedUrl("/iam/account-linking/SAML/done"))
      .andExpect(authenticated().withUsername("test"))
      .andReturn()
      .getRequest()
      .getSession();


    String expectedErrorMessage = String
      .format("SAML account '[%s] %s' is already linked to user 'test'", DEFAULT_IDP_ID, T2_EPUID);

    mvc.perform(get("/iam/account-linking/SAML/done").session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, equalTo(expectedErrorMessage)));

  }

  @Test
  @WithMockUser(username = "test")
  public void samlAccountLinkingExternalAuthnErrorRedirectsToDashboard() throws Throwable {
    MockHttpSession session = (MockHttpSession) mvc
      .perform(post("/iam/account-linking/SAML").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get(samlLoginUrl()).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getRequest()
      .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
        Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildNoAudienceInvalidResponse(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
        .session(session))
      .andExpect(authenticated().withUsername("test"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, nullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY, nullValue()))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andReturn()
      .getRequest()
      .getSession();
  }

  @Test
  @WithMockUser(username = TEST_100_USER)
  public void samlAccountLinkingUnderstandsIdParam() throws Exception {
    mvc
      .perform(
          post("/iam/account-linking/SAML").param("id", "https://test.idp").with(csrf().asHeader()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/saml/login?idpId=https://test.idp"))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, nullValue()))
      .andExpect(
          request().sessionAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, notNullValue()))
      .andExpect(request().sessionAttribute(ACCOUNT_LINKING_SESSION_KEY,
          Matchers.equalTo("/iam/account-linking/SAML")))
      .andReturn()
      .getRequest()
      .getSession();
  }
}
