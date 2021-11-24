package it.infn.mw.iam.core.user.exception;

public class MfaSecretAlreadyBoundException extends IamAccountException {
  
  /**
   * TODO assign serialVersionUID
   */
  // private static final long serialVersionUID = 4103663720620113509L;

  public MfaSecretAlreadyBoundException(String message) {
    super(message);
  }
}
