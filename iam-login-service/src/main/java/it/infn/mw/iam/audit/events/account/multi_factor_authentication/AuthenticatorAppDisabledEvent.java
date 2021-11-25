package it.infn.mw.iam.audit.events.account.multi_factor_authentication;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthenticatorAppDisabledEvent extends MultiFactorEvent {

  public static final String TEMPLATE = "Authenticator app MFA disabled on  account '%s'";

  // TODO add this in
  // private static final long serialVersionUID = 3213253939764135733L;

  public AuthenticatorAppDisabledEvent(Object source, IamAccount account) {
    super(source, account, String.format(TEMPLATE, account.getUsername()));
  }
}
