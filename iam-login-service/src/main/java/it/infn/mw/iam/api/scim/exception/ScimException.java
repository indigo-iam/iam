package it.infn.mw.iam.api.scim.exception;

public class ScimException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public ScimException(String message) {
    super(message);
  }
}
