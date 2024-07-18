package it.infn.mw.iam.core.oauth;

public class AdminScopeNotAllowedException extends IllegalArgumentException {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public AdminScopeNotAllowedException(String message) {
    super(message);
  }
}
