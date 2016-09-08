package it.infn.mw.iam.api.account;

public interface PasswordResetService {

  public Boolean checkResetKey(String resetKey);

  public void changePassword(String resetKey, String password);

  public void forgotPassword(String email);

}
