package it.infn.mw.iam.authn.oidc.service;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;

public interface OidcUserDetailsService {

  Object loadUserByOIDC(OIDCAuthenticationToken token);


}
