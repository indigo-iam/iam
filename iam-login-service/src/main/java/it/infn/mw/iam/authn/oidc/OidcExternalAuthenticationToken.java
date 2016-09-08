package it.infn.mw.iam.authn.oidc;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;

public class OidcExternalAuthenticationToken
    extends AbstractExternalAuthenticationToken<OIDCAuthenticationToken> {

  private static final long serialVersionUID = -1297301102973236138L;

  public OidcExternalAuthenticationToken(OIDCAuthenticationToken authn, Object principal,
      Object credentials) {
    super(authn, principal, credentials);
  }

  public OidcExternalAuthenticationToken(OIDCAuthenticationToken authn, Date tokenExpiration,
      Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
    super(authn, tokenExpiration, principal, credentials, authorities);
  }

  @Override
  public Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor) {

    return visitor.buildInfoMap(this);
  }

}
