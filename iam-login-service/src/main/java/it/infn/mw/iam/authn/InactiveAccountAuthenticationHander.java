package it.infn.mw.iam.authn;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.infn.mw.iam.persistence.model.IamAccount;

public interface InactiveAccountAuthenticationHander {

  public void handleInactiveAccount(IamAccount account) throws UsernameNotFoundException;

}
