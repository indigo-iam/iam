package it.infn.mw.iam.api.account.password_reset.error;

public class InvalidEmailAddressError extends RuntimeException {


  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public InvalidEmailAddressError(String message) {
    super(message);
  }

}
