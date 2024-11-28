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
package it.infn.mw.iam.test.multi_factor_authentication;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

public class MultiFactorTestSupport extends IamTotpMfaCommons{
  public static final String TEST_USERNAME = "test-user";
  public static final String TEST_UUID = "a23deabf-88a7-47af-84b5-1d535a1b267c";
  public static final String TEST_EMAIL = "test@example.org";
  public static final String TEST_GIVEN_NAME = "Test";
  public static final String TEST_FAMILY_NAME = "User";
  public static final String TOTP_USERNAME = "test-mfa-user";
  public static final String TOTP_UUID = "ceb173b4-28e3-43ad-aaf7-15d3730e2b90";
  public static final String TOTP_EMAIL = "test-mfa@example.org";
  public static final String TOTP_GIVEN_NAME = "Test";
  public static final String TOTP_FAMILY_NAME = "Mfa";

  protected final IamAccount TEST_ACCOUNT;
  protected final IamAccount TOTP_MFA_ACCOUNT;
  protected final IamTotpMfa TOTP_MFA;

  public MultiFactorTestSupport() {
    TEST_ACCOUNT = IamAccount.newAccount();
    TEST_ACCOUNT.setUsername(TEST_USERNAME);
    TEST_ACCOUNT.setUuid(TEST_UUID);
    TEST_ACCOUNT.getUserInfo().setEmail(TEST_EMAIL);
    TEST_ACCOUNT.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    TEST_ACCOUNT.getUserInfo().setFamilyName(TEST_FAMILY_NAME);

    TEST_ACCOUNT.touch();

    TOTP_MFA_ACCOUNT = IamAccount.newAccount();
    TOTP_MFA_ACCOUNT.setUsername(TOTP_USERNAME);
    TOTP_MFA_ACCOUNT.setUuid(TOTP_UUID);
    TOTP_MFA_ACCOUNT.getUserInfo().setEmail(TOTP_EMAIL);
    TOTP_MFA_ACCOUNT.getUserInfo().setGivenName(TOTP_GIVEN_NAME);
    TOTP_MFA_ACCOUNT.getUserInfo().setFamilyName(TOTP_FAMILY_NAME);

    TOTP_MFA_ACCOUNT.touch();

    TOTP_MFA = new IamTotpMfa();
    TOTP_MFA.setAccount(TOTP_MFA_ACCOUNT);
    TOTP_MFA.setSecret(
        IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(
            TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT));
    TOTP_MFA.setActive(true);
    TOTP_MFA.touch();
  }

  protected void resetTestAccount() {
    TEST_ACCOUNT.setUsername(TEST_USERNAME);
    TEST_ACCOUNT.setUuid(TEST_UUID);
    TEST_ACCOUNT.getUserInfo().setEmail(TEST_EMAIL);
    TEST_ACCOUNT.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    TEST_ACCOUNT.getUserInfo().setFamilyName(TEST_FAMILY_NAME);

    TEST_ACCOUNT.touch();
  }

  protected void resetTotpAccount() {
    TOTP_MFA_ACCOUNT.setUsername(TOTP_USERNAME);
    TOTP_MFA_ACCOUNT.setUuid(TOTP_UUID);
    TOTP_MFA_ACCOUNT.getUserInfo().setEmail(TOTP_EMAIL);
    TOTP_MFA_ACCOUNT.getUserInfo().setGivenName(TOTP_GIVEN_NAME);
    TOTP_MFA_ACCOUNT.getUserInfo().setFamilyName(TOTP_FAMILY_NAME);

    TOTP_MFA_ACCOUNT.touch();

    TOTP_MFA.setAccount(TOTP_MFA_ACCOUNT);
    TOTP_MFA.setSecret(
        IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(
            TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT));
    TOTP_MFA.setActive(true);
    TOTP_MFA.touch();
  }

  protected IamAccount cloneAccount(IamAccount account) {
    IamAccount newAccount = IamAccount.newAccount();
    newAccount.setUuid(account.getUuid());
    newAccount.setUsername(account.getUsername());
    newAccount.getUserInfo().setEmail(account.getUserInfo().getEmail());
    newAccount.getUserInfo().setGivenName(account.getUserInfo().getGivenName());
    newAccount.getUserInfo().setFamilyName(account.getUserInfo().getFamilyName());

    newAccount.touch();

    return newAccount;
  }

  protected IamTotpMfa cloneTotpMfa(IamTotpMfa totpMfa) {
    IamTotpMfa newTotpMfa = new IamTotpMfa();
    newTotpMfa.setAccount(totpMfa.getAccount());
    newTotpMfa.setSecret(totpMfa.getSecret());
    newTotpMfa.setActive(totpMfa.isActive());

    newTotpMfa.touch();

    return newTotpMfa;
  }

  public String getEncryptedCode(String plaintext, String key) {
    return IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(plaintext, key);
  }
}
