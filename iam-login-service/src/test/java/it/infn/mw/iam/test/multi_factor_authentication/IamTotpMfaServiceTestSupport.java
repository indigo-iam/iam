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
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

public class IamTotpMfaServiceTestSupport extends IamTotpMfaCommons {

  public static final String PASSWORD = "password";

  public static final String TOTP_MFA_ACCOUNT_UUID = "b3e7dd7f-a1ac-eda0-371d-b902a6c5cee2";
  public static final String TOTP_MFA_ACCOUNT_USERNAME = "totp";
  public static final String TOTP_MFA_ACCOUNT_EMAIL = "totp@example.org";
  public static final String TOTP_MFA_ACCOUNT_GIVEN_NAME = "Totp";
  public static final String TOTP_MFA_ACCOUNT_FAMILY_NAME = "Mfa";

  public static final String TOTP_CODE = "123456";

  protected final IamAccount TOTP_MFA_ACCOUNT;
  protected final IamAuthority ROLE_USER_AUTHORITY;

  protected final IamTotpMfa TOTP_MFA;

  public IamTotpMfaServiceTestSupport() {
    ROLE_USER_AUTHORITY = new IamAuthority("ROLE_USER");

    TOTP_MFA_ACCOUNT = IamAccount.newAccount();
    TOTP_MFA_ACCOUNT.setUuid(TOTP_MFA_ACCOUNT_UUID);
    TOTP_MFA_ACCOUNT.setUsername(TOTP_MFA_ACCOUNT_USERNAME);
    TOTP_MFA_ACCOUNT.getUserInfo().setEmail(TOTP_MFA_ACCOUNT_EMAIL);
    TOTP_MFA_ACCOUNT.getUserInfo().setGivenName(TOTP_MFA_ACCOUNT_GIVEN_NAME);
    TOTP_MFA_ACCOUNT.getUserInfo().setFamilyName(TOTP_MFA_ACCOUNT_FAMILY_NAME);

    TOTP_MFA = new IamTotpMfa();
    TOTP_MFA.setAccount(TOTP_MFA_ACCOUNT);
    TOTP_MFA.setSecret(getEncryptedCode(TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT));
    TOTP_MFA.setActive(true);

    TOTP_MFA.touch();
  }

  public IamAccount cloneAccount(IamAccount account) {
    IamAccount newAccount = IamAccount.newAccount();
    newAccount.setUuid(account.getUuid());
    newAccount.setUsername(account.getUsername());
    newAccount.getUserInfo().setEmail(account.getUserInfo().getEmail());
    newAccount.getUserInfo().setGivenName(account.getUserInfo().getGivenName());
    newAccount.getUserInfo().setFamilyName(account.getUserInfo().getFamilyName());

    newAccount.touch();

    return newAccount;
  }

  public IamTotpMfa cloneTotpMfa(IamTotpMfa totpMfa) {
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
