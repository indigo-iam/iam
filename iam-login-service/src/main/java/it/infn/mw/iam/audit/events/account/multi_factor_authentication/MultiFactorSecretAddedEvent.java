package it.infn.mw.iam.audit.events.account.multi_factor_authentication;

import it.infn.mw.iam.persistence.model.IamAccount;

public class MultiFactorSecretAddedEvent extends MultiFactorEvent {

  public static final String TEMPLATE = "Multi-factor secret added to account '%s'";

  // TODO add this in
  // private static final long serialVersionUID = 3213253939764135733L;

  public MultiFactorSecretAddedEvent(Object source, IamAccount account) {
    super(source, account, String.format(TEMPLATE, account.getUsername()));
  }
}
