package it.infn.mw.iam.api.account.password_reset.error;

public class InvalidPasswordError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public InvalidPasswordError(String message) {
    super(message);
  }

}
