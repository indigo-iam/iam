package it.infn.mw.iam.api.account;

public class InvalidPasswordError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public InvalidPasswordError(String message) {
    super(message);
  }

}
