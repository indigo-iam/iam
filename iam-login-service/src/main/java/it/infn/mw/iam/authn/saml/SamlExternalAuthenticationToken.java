package it.infn.mw.iam.authn.saml;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;

public class SamlExternalAuthenticationToken
    extends AbstractExternalAuthenticationToken<ExpiringUsernameAuthenticationToken> {

  private static final long serialVersionUID = -7854473523011856692L;

  public SamlExternalAuthenticationToken(ExpiringUsernameAuthenticationToken authn,
      Object principal, Object credentials) {
    super(authn, principal, credentials);
  }

  public SamlExternalAuthenticationToken(ExpiringUsernameAuthenticationToken authn,
      Date tokenExpiration, Object principal, Object credentials,
      Collection<? extends GrantedAuthority> authorities) {
    super(authn, tokenExpiration, principal, credentials, authorities);
  }

  @Override
  public Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor) {

    return visitor.buildInfoMap(this);
  }

}
