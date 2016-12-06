package it.infn.mw.iam.api.account.password_reset;

/**
 * 
 * The IAM password reset service
 *
 */
public interface PasswordResetService {


  /**
   * Validates a password reset token.
   * 
   * @param resetToken the password reset token to be validated
   * 
   * @throws InvalidPasswordResetTokenError if the password reset token is not valid
   */
  public void validateResetToken(String resetToken);

  /**
   * Resets the password for an account, given a valid password reset token
   * 
   * @param resetToken the password reset token
   * 
   * @param password the password to be set
   * 
   * @throws InvalidPasswordResetTokenError if the password reset token is not valid
   */
  public void resetPassword(String resetToken, String password);

  /**
   * Creates a password reset token for the account linked with the email passed as argument.
   * 
   * @param email the email linked to the account for which the password must be reset
   */
  public void createPasswordResetToken(String email);

  /**
   * Updates the password for the account identified by both username and the current active password
   *
   * @param username the account username
   *
   * @param oldPassword the current active password
   *
   * @param newPassword the password to be set
   *
   * @throws UserNotActiveOrNotVerified if the user is not enabled
   *
   * @throws BadUserPasswordError if the @oldPassword doesn't match
   */
  public void updatePassword(String username, String oldPassword, String newPassword);

}
