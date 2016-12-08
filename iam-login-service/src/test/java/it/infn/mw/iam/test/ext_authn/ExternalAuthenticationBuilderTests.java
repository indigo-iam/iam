package it.infn.mw.iam.test.ext_authn;

import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.OIDC_TYPE;
import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.SAML_TYPE;
import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.TYPE_ATTR;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.SamlIdResolvers;

public class ExternalAuthenticationBuilderTests {

  @Test
  public void testBuildOidcInfoMap() {
    DefaultExternalAuthenticationInfoBuilder builder =
        new DefaultExternalAuthenticationInfoBuilder();

    OidcExternalAuthenticationToken mockToken = mock(OidcExternalAuthenticationToken.class);
    OIDCAuthenticationToken token = mock(OIDCAuthenticationToken.class);

    when(mockToken.getExternalAuthentication()).thenReturn(token);
    when(token.getSub()).thenReturn("sub");
    when(token.getIssuer()).thenReturn("iss");

    Map<String, String> infoMap = builder.buildInfoMap(mockToken);
    assertThat(infoMap.get(TYPE_ATTR), Matchers.equalTo(OIDC_TYPE));
    assertThat(infoMap.get("sub"), Matchers.equalTo("sub"));
    assertThat(infoMap.get("iss"), Matchers.equalTo("iss"));

  }

  @Test
  public void testBuildSamlInfoMap() {
    DefaultExternalAuthenticationInfoBuilder builder =
        new DefaultExternalAuthenticationInfoBuilder();

    SamlExternalAuthenticationToken mockToken = mock(SamlExternalAuthenticationToken.class);
    ExpiringUsernameAuthenticationToken token = mock(ExpiringUsernameAuthenticationToken.class);
    SAMLCredential cred = mock(SAMLCredential.class);
    when(token.getCredentials()).thenReturn(cred);
    when(mockToken.getExternalAuthentication()).thenReturn(token);
    when(token.getCredentials()).thenReturn(cred);
    when(cred.getRemoteEntityID()).thenReturn("idpId");
    when(cred.getAttributeAsString(SamlIdResolvers.EPUID_NAME)).thenReturn("epuid");
    when(cred.getAttributeAsString(SamlIdResolvers.EPPN_NAME)).thenReturn("eppn");

    Map<String, String> infoMap = builder.buildInfoMap(mockToken);
    assertThat(infoMap.get(TYPE_ATTR), Matchers.equalTo(SAML_TYPE));
    assertThat(infoMap.get("epuid"), Matchers.equalTo("epuid"));
    assertThat(infoMap.get("eppn"), Matchers.equalTo("eppn"));

  }

}
