package it.infn.mw.iam.api.account_linking;

import java.security.Principal;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;

public interface AccountLinkingService {

  void linkExternalAccount(Principal authenticatedUser,
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken);

  void unlinkExternalAccount(Principal authenticatedUser, ExternalAuthenticationType type,
      String iss, String sub);

}
