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

import java.time.Instant;
import java.util.Date;

import it.infn.mw.iam.persistence.model.IamAccount;
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

  protected IamAccount getAccount(Instant instant) {

    IamAccount a = IamAccount.newAccount();
    a.setUuid(TOTP_MFA_ACCOUNT_UUID);
    a.setUsername(TOTP_MFA_ACCOUNT_USERNAME);
    a.getUserInfo().setEmail(TOTP_MFA_ACCOUNT_EMAIL);
    a.getUserInfo().setGivenName(TOTP_MFA_ACCOUNT_GIVEN_NAME);
    a.getUserInfo().setFamilyName(TOTP_MFA_ACCOUNT_FAMILY_NAME);
    a.setCreationTime(Date.from(instant));
    a.setLastUpdateTime(Date.from(instant));
    return a;
  }

  protected IamTotpMfa getTotpMfaForAccount(IamAccount account, Instant instant) {

    IamTotpMfa t = new IamTotpMfa(instant);
    t.setAccount(account);
    t.setSecret(getEncryptedCode(TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT));
    t.setActive(true);
    t.touch(instant);
    return t;
  }

  public String getEncryptedCode(String plaintext, String key) {
    return IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(plaintext, key);
  }
}
