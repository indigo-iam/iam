package it.infn.mw.iam.authn.saml;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;

public class IamSamlAuthenticationProvider extends SAMLAuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    ExpiringUsernameAuthenticationToken token =
        (ExpiringUsernameAuthenticationToken) super.authenticate(authentication);

    if (token == null) {
      return null;
    }

    User user = (User) token.getDetails();

    SamlExternalAuthenticationToken extAuthnToken =
        new SamlExternalAuthenticationToken(token, token.getTokenExpiration(), user.getUsername(),
            token.getCredentials(), token.getAuthorities());

    return extAuthnToken;
  }

}
