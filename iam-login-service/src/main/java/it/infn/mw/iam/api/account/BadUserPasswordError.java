package it.infn.mw.iam.api.account;

public class BadUserPasswordError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public BadUserPasswordError(String message) {
    super(message);
  }

}
