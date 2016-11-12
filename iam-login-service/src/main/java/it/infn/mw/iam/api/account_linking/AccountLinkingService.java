package it.infn.mw.iam.api.account_linking;

import java.security.Principal;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;

public interface AccountLinkingService {

  void linkExternalAccount(Principal authenticatedUser,
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken);

}
