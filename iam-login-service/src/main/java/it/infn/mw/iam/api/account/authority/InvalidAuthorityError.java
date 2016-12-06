package it.infn.mw.iam.api.account.authority;

public class InvalidAuthorityError extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public InvalidAuthorityError(String message) {
    super(message);
  }

}
