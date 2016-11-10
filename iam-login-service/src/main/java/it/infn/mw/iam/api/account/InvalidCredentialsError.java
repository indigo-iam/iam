package it.infn.mw.iam.api.account;

public class InvalidCredentialsError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public InvalidCredentialsError(String message) {
    super(message);
  }

}
