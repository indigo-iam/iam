package it.infn.mw.iam.api.account;

public class UserNotActiveOrNotVerified extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public UserNotActiveOrNotVerified(String message) {
    super(message);
  }

}
