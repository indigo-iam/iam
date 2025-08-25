package it.infn.mw.iam.core.oidc;

public class FederationError {

  private final String error;
  private final String errorDescription;

  public FederationError(String error, String errorDescription) {
    this.error = error;
    this.errorDescription = errorDescription;
  }

  public String getError() {
    return error;
  }

  public String getErrorDescription() {
    return errorDescription;
  }
}
