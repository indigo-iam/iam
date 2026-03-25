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

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

public class MultiFactorTestSupport extends IamTotpMfaCommons {

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

  protected IamAccount getTestAccount(Instant instant) {
    IamAccount a = IamAccount.newAccount();
    a.setUsername(TEST_USERNAME);
    a.setUuid(TEST_UUID);
    a.getUserInfo().setEmail(TEST_EMAIL);
    a.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    a.getUserInfo().setFamilyName(TEST_FAMILY_NAME);
    a.touch(instant);
    return a;
  }

  protected IamAccount getTotpMfaAccount(Instant instant) {
    IamAccount a = IamAccount.newAccount();
    a.setUsername(TOTP_USERNAME);
    a.setUuid(TOTP_UUID);
    a.getUserInfo().setEmail(TOTP_EMAIL);
    a.getUserInfo().setGivenName(TOTP_GIVEN_NAME);
    a.getUserInfo().setFamilyName(TOTP_FAMILY_NAME);
    a.touch(instant);
    return a;
  }

  protected IamTotpMfa getTotpMfaFor(IamAccount account, Instant instant) {
    IamTotpMfa t = new IamTotpMfa(instant);
    t.setAccount(account);
    t.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(TOTP_MFA_SECRET,
        KEY_TO_ENCRYPT_DECRYPT));
    t.setActive(true);
    return t;
  }

  public String getEncryptedCode(String plaintext, String key) {
    return IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(plaintext, key);
  }
}
