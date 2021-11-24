package it.infn.mw.iam.core.user.exception;

public class MfaSecretNotFoundException extends IamAccountException {

  /**
   * TODO assign serialVersionUID
   */
  // private static final long serialVersionUID = 4103663720620113509L;

  public MfaSecretNotFoundException(String message) {
    super(message);
  }
}
