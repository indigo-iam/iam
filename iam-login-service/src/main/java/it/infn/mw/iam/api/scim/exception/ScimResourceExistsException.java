package it.infn.mw.iam.api.scim.exception;


public class ScimResourceExistsException extends ScimException {

  private static final long serialVersionUID = 1L;

  public ScimResourceExistsException(String s) {
    super(s);
  }
}
