package it.infn.mw.iam.authn;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;

public interface ExternalAccountLinker {

  void linkToIamAccount(IamAccount targetAccount, OidcExternalAuthenticationToken token);

  void linkToIamAccount(IamAccount targetAccount, SamlExternalAuthenticationToken token);

}
