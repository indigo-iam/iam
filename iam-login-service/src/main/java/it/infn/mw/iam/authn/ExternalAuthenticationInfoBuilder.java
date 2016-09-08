package it.infn.mw.iam.authn;

import java.util.Map;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;

public interface ExternalAuthenticationInfoBuilder {

  Map<String, String> buildInfoMap(SamlExternalAuthenticationToken token);

  Map<String, String> buildInfoMap(OidcExternalAuthenticationToken token);

}
