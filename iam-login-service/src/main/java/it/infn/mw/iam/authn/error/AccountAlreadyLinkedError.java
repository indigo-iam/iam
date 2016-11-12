package it.infn.mw.iam.authn.error;

public class AccountAlreadyLinkedError extends RuntimeException {

  /**
   *
   */
  private static final long serialVersionUID = 6262290472090440129L;

  public AccountAlreadyLinkedError(String message) {
    super(message);

  }


}
