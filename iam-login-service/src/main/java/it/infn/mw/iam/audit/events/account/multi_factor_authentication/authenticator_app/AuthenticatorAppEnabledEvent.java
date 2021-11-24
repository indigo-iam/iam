package it.infn.mw.iam.audit.events.account.multi_factor_authentication.authenticator_app;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthenticatorAppEnabledEvent extends AccountEvent {

  public static final String TEMPLATE = "Account '%s' has enabled MFA through authenticator app";

  // TODO add this in
  // private static final long serialVersionUID = 3213253939764135733L;

  public AuthenticatorAppEnabledEvent(Object source, IamAccount account) {
    super(source, account, String.format(TEMPLATE, account.getUsername()));
  }
}
