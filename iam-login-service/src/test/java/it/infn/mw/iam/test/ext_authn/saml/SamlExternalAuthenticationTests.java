package it.infn.mw.iam.test.ext_authn.saml;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.SAML;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.saml.SamlUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, SamlTestConfig.class})
@WebAppConfiguration
public class SamlExternalAuthenticationTests extends SamlExternalAuthenticationTestSupport {

  @Test
  public void testSuccessfulExternalUnregisteredUserAuthentication() throws Throwable {

    MockHttpSession session =
	(MockHttpSession) mvc.perform(MockMvcRequestBuilders.get(samlLoginUrl()))
	  .andExpect(MockMvcResultMatchers.status().isOk())
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
      .andExpect(redirectedUrl("/register"))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(get(EXT_AUTHN_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.given_name").value(equalTo(T1_GIVEN_NAME)))
      .andExpect(jsonPath("$.family_name").value(equalTo(T1_SN)))
      .andExpect(jsonPath("$.email").value(equalTo(T1_MAIL)))
      .andExpect(jsonPath("$.type").value(equalTo(SAML.name())))
      .andExpect(jsonPath("$.issuer").value(equalTo(DEFAULT_IDP_ID)))
      .andExpect(jsonPath("$.subject").value(equalTo(T1_EPUID)));

  }

  @Test
  public void testExternalAuthenticationFailureRedirectsToLoginPage() throws Throwable {

    MockHttpSession session =
	(MockHttpSession) mvc.perform(MockMvcRequestBuilders.get(samlLoginUrl()))
	  .andExpect(MockMvcResultMatchers.status().isOk())
	  .andReturn()
	  .getRequest()
	  .getSession();

    AuthnRequest authnRequest = getAuthnRequestFromSession(session);

    assertThat(authnRequest.getAssertionConsumerServiceURL(),
	Matchers.equalTo("http://localhost:8080/saml/SSO"));

    Response r = buildNoAttributesInvalidResponse(authnRequest);

    session = (MockHttpSession) mvc
      .perform(post(authnRequest.getAssertionConsumerServiceURL())
	.contentType(MediaType.APPLICATION_FORM_URLENCODED)
	.param("SAMLResponse", SamlUtils.signAndSerializeToBase64(r))
	.session(session))
      .andExpect(redirectedUrlPattern("/login**"))
      .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
      .andReturn()
      .getRequest()
      .getSession();

  }

}
