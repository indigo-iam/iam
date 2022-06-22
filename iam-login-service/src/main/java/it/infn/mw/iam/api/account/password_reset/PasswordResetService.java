/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.api.account.password_reset;

/**
 * 
 * The IAM password reset service
 *
 */
@SuppressWarnings("unused")
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
