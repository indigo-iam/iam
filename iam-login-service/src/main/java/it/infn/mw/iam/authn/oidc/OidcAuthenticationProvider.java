package it.infn.mw.iam.authn.oidc;

import java.text.ParseException;
import java.util.Date;

import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;

import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;

public class OidcAuthenticationProvider extends OIDCAuthenticationProvider {

  public static final Logger LOG = LoggerFactory.getLogger(OidcAuthenticationProvider.class);

  private final OidcUserDetailsService userDetailsService;

  @Autowired
  public OidcAuthenticationProvider(OidcUserDetailsService userDetailsService) {

    this.userDetailsService = userDetailsService;
  }

  private Date getExpirationTimeFromOIDCAuthenticationToken(OIDCAuthenticationToken token) {
    try {
      return token.getIdToken().getJWTClaimsSet().getExpirationTime();
    } catch (ParseException e) {
      throw new BadCredentialsException("Could not extract expiration time from ID token", e);
    }
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    OIDCAuthenticationToken token = (OIDCAuthenticationToken) super.authenticate(authentication);

    if (token == null) {
      return null;
    }

    User user = (User) userDetailsService.loadUserByOIDC(token);

    return new OidcExternalAuthenticationToken(token,
	getExpirationTimeFromOIDCAuthenticationToken(token), user.getUsername(), null,
	user.getAuthorities());
  }

}
