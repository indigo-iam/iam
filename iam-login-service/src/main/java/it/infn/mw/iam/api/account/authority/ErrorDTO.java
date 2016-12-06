package it.infn.mw.iam.api.account.authority;

public class ErrorDTO {

  private final String error;

  public static ErrorDTO fromString(String error) {
    return new ErrorDTO(error);
  }

  private ErrorDTO(String error) {
    this.error = error;
  }

  public String getError() {
    return error;
  }

}
