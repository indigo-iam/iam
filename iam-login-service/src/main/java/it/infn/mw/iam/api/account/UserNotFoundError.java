package it.infn.mw.iam.api.account;

public class UserNotFoundError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public UserNotFoundError(String message) {
    super(message);
  }

}
