package it.infn.mw.iam.audit.events.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountLinkedEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  @JsonIgnoreProperties({"email", "givenName", "familyName"})
  private final ExternalAuthenticationRegistrationInfo externalAccountInfo;

  public AccountLinkedEvent(Object source, IamAccount account,
      ExternalAuthenticationRegistrationInfo externalAccountInfo, String message) {
    super(source, account, message);
    this.externalAccountInfo = externalAccountInfo;
  }

  public ExternalAuthenticationRegistrationInfo getExternalAccountInfo() {
    return externalAccountInfo;
  }
}
