package it.infn.mw.iam.test.ext_authn;


import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;

public class ExternalAuthenticationRegistrationInfoTests {

  @Test
  public void testOidcMinimalInfoConversion() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);

    when(token.getSub()).thenReturn("test-oidc-subject");
    when(token.getIssuer()).thenReturn("test-oidc-issuer");

    OidcExternalAuthenticationToken extAuthToken =
	new OidcExternalAuthenticationToken(token, "test-oidc-subject", null);

    ExternalAuthenticationRegistrationInfo uri = extAuthToken.toExernalAuthenticationInfo();

    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.OIDC));
    assertThat(uri.getGivenName(), Matchers.nullValue());
    assertThat(uri.getFamilyName(), Matchers.nullValue());
    assertThat(uri.getEmail(), Matchers.nullValue());
    assertThat(uri.getSubject(), equalTo("test-oidc-subject"));
    assertThat(uri.getIssuer(), equalTo("test-oidc-issuer"));

  }

  @Test
  public void testOidcEmailAndNameReturnedIfPresent() {
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);

    UserInfo userinfo = mock(UserInfo.class);

    when(userinfo.getEmail()).thenReturn("test@test.org");

    when(userinfo.getGivenName()).thenReturn("Test Given Name");
    when(userinfo.getFamilyName()).thenReturn("Test Family Name");

    when(token.getSub()).thenReturn("test-oidc-subject");
    when(token.getIssuer()).thenReturn("test-oidc-issuer");
    when(token.getUserInfo()).thenReturn(userinfo);

    OidcExternalAuthenticationToken extAuthToken =
	new OidcExternalAuthenticationToken(token, "test-oidc-subject", null);

    ExternalAuthenticationRegistrationInfo uri = extAuthToken.toExernalAuthenticationInfo();

    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.OIDC));
    assertThat(uri.getSubject(), equalTo("test-oidc-subject"));
    assertThat(uri.getIssuer(), equalTo("test-oidc-issuer"));
    assertThat(uri.getGivenName(), equalTo("Test Given Name"));
    assertThat(uri.getFamilyName(), equalTo("Test Family Name"));
    assertThat(uri.getEmail(), equalTo("test@test.org"));



  }

  @Test
  public void testSamlMinimalInfoConversion() {
    ExpiringUsernameAuthenticationToken token = mock(ExpiringUsernameAuthenticationToken.class);
    SAMLCredential cred = mock(SAMLCredential.class);

    when(token.getCredentials()).thenReturn(cred);
    when(token.getName()).thenReturn("test-saml-subject");
    when(cred.getRemoteEntityID()).thenReturn("test-saml-issuer");

    SamlExternalAuthenticationToken extAuthToken =
	new SamlExternalAuthenticationToken(token, token.getTokenExpiration(), "test-saml-subject",
	    token.getCredentials(), token.getAuthorities());

    ExternalAuthenticationRegistrationInfo uri = extAuthToken.toExernalAuthenticationInfo();
    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.SAML));
    assertThat(uri.getSubject(), equalTo("test-saml-subject"));
    assertThat(uri.getIssuer(), equalTo("test-saml-issuer"));
    assertThat(uri.getGivenName(), Matchers.nullValue());
    assertThat(uri.getFamilyName(), Matchers.nullValue());
    assertThat(uri.getEmail(), Matchers.nullValue());

  }

  @Test
  public void testSamlEmailAndNameReturnedIfPresent() {
    ExpiringUsernameAuthenticationToken token = mock(ExpiringUsernameAuthenticationToken.class);

    SAMLCredential cred = mock(SAMLCredential.class);
    when(cred.getRemoteEntityID()).thenReturn("test-saml-issuer");

    when(cred.getAttributeAsString(SamlExternalAuthenticationToken.OID_GIVEN_NAME))
      .thenReturn("Test Given Name");
    when(cred.getAttributeAsString(SamlExternalAuthenticationToken.OID_SN))
      .thenReturn("Test Family Name");
    when(cred.getAttributeAsString(SamlExternalAuthenticationToken.OID_MAIL))
      .thenReturn("test@test.org");

    when(token.getCredentials()).thenReturn(cred);
    when(token.getName()).thenReturn("test-saml-subject");


    SamlExternalAuthenticationToken extAuthToken =
	new SamlExternalAuthenticationToken(token, token.getTokenExpiration(), "test-saml-subject",
	    token.getCredentials(), token.getAuthorities());

    ExternalAuthenticationRegistrationInfo uri = extAuthToken.toExernalAuthenticationInfo();
    assertThat(uri.getType(), equalTo(ExternalAuthenticationType.SAML));
    assertThat(uri.getSubject(), equalTo("test-saml-subject"));
    assertThat(uri.getIssuer(), equalTo("test-saml-issuer"));
    assertThat(uri.getGivenName(), equalTo("Test Given Name"));
    assertThat(uri.getFamilyName(), equalTo("Test Family Name"));
    assertThat(uri.getEmail(), equalTo("test@test.org"));

  }

}
