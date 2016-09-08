package it.infn.mw.iam.authn.util;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.security.core.Authentication;

import com.google.common.collect.ImmutableSet;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;

public class AuthenticationUtils {

  private static final ImmutableSet<String> SUPPORTED_EXTERNAL_AUTHN_TOKENS =
      ImmutableSet.of(SamlExternalAuthenticationToken.class.getName(),
          OidcExternalAuthenticationToken.class.getName());

  public static boolean isSupportedExternalAuthenticationToken(Authentication authn) {

    if (authn instanceof SavedUserAuthentication) {
      SavedUserAuthentication savedAuth = (SavedUserAuthentication) authn;

      if (savedAuth.getSourceClass() != null) {
        return SUPPORTED_EXTERNAL_AUTHN_TOKENS.contains(savedAuth.getSourceClass());
      }

    }
    return false;
  }

  private AuthenticationUtils() {}

}
