package it.infn.mw.iam.test.util.saml;

import static org.mockito.Mockito.when;

import org.mockito.Mockito;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.test.ext_authn.saml.SamlExternalAuthenticationTestSupport;
import it.infn.mw.iam.test.util.SecurityContextBuilderSupport;

public class SamlSecurityContextBuilder extends SecurityContextBuilderSupport {

  SAMLCredential samlCredential;

  public SamlSecurityContextBuilder() {
    samlCredential = Mockito.mock(SAMLCredential.class);
    issuer = SamlExternalAuthenticationTestSupport.DEFAULT_IDP_ID;
    subject = "test-saml-user";
  }

  @Override
  public SecurityContextBuilderSupport email(String email) {
    when(samlCredential.getAttributeAsString(SamlAttributeNames.mail)).thenReturn(email);
    return this;
  }

  @Override
  public SecurityContextBuilderSupport name(String givenName, String familyName) {

    if (!Strings.isNullOrEmpty(givenName) && Strings.isNullOrEmpty(familyName)) {
      when(samlCredential.getAttributeAsString(SamlAttributeNames.givenName)).thenReturn(givenName);
      when(samlCredential.getAttributeAsString(SamlAttributeNames.sn)).thenReturn(familyName);
    }

    return this;
  }

  @Override
  public SecurityContext buildSecurityContext() {
    SecurityContext context = SecurityContextHolder.createEmptyContext();

    when(samlCredential.getRemoteEntityID()).thenReturn(issuer);

    ExpiringUsernameAuthenticationToken samlToken = new ExpiringUsernameAuthenticationToken(
	expirationTime, username, samlCredential, authorities);

    SamlExternalAuthenticationToken token = new SamlExternalAuthenticationToken(samlToken,
	samlToken.getTokenExpiration(), username, samlToken.getCredentials(), authorities);

    context.setAuthentication(token);

    return context;

  }

}
