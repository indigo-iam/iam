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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;

public class IamTotpMfaServiceTestSupport {

  public static final String PASSWORD = "password";

  public static final String TOTP_MFA_ACCOUNT_UUID = "b3e7dd7f-a1ac-eda0-371d-b902a6c5cee2";
  public static final String TOTP_MFA_ACCOUNT_USERNAME = "totp";
  public static final String TOTP_MFA_ACCOUNT_EMAIL = "totp@example.org";
  public static final String TOTP_MFA_ACCOUNT_GIVEN_NAME = "Totp";
  public static final String TOTP_MFA_ACCOUNT_FAMILY_NAME = "Mfa";

  public static final String TOTP_MFA_SECRET = "secret";

  public static final String TOTP_RECOVERY_CODE_STRING_1 = "code-1";
  public static final String TOTP_RECOVERY_CODE_STRING_2 = "code-2";
  public static final String TOTP_RECOVERY_CODE_STRING_3 = "code-3";
  public static final String TOTP_RECOVERY_CODE_STRING_4 = "code-4";
  public static final String TOTP_RECOVERY_CODE_STRING_5 = "code-5";
  public static final String TOTP_RECOVERY_CODE_STRING_6 = "code-6";
  public static final String TOTP_RECOVERY_CODE_STRING_7 = "code-7";
  public static final String TOTP_RECOVERY_CODE_STRING_8 = "code-8";
  public static final String TOTP_RECOVERY_CODE_STRING_9 = "code-9";
  public static final String TOTP_RECOVERY_CODE_STRING_10 = "code-10";
  public static final String TOTP_RECOVERY_CODE_STRING_11 = "code-11";
  public static final String TOTP_RECOVERY_CODE_STRING_12 = "code-12";

  protected final IamAccount TOTP_MFA_ACCOUNT;
  protected final IamAuthority ROLE_USER_AUTHORITY;

  protected final IamTotpMfa TOTP_MFA;

  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_1;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_2;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_3;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_4;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_5;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_6;

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
    TOTP_MFA.setSecret(TOTP_MFA_SECRET);
    TOTP_MFA.setActive(true);

    TOTP_RECOVERY_CODE_1 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_2 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_3 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_4 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_5 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_6 = new IamTotpRecoveryCode(TOTP_MFA);

    TOTP_RECOVERY_CODE_1.setCode(TOTP_RECOVERY_CODE_STRING_1);
    TOTP_RECOVERY_CODE_2.setCode(TOTP_RECOVERY_CODE_STRING_2);
    TOTP_RECOVERY_CODE_3.setCode(TOTP_RECOVERY_CODE_STRING_3);
    TOTP_RECOVERY_CODE_4.setCode(TOTP_RECOVERY_CODE_STRING_4);
    TOTP_RECOVERY_CODE_5.setCode(TOTP_RECOVERY_CODE_STRING_5);
    TOTP_RECOVERY_CODE_6.setCode(TOTP_RECOVERY_CODE_STRING_6);

    TOTP_MFA
      .setRecoveryCodes(new HashSet<>(Arrays.asList(TOTP_RECOVERY_CODE_1, TOTP_RECOVERY_CODE_2,
          TOTP_RECOVERY_CODE_3, TOTP_RECOVERY_CODE_4, TOTP_RECOVERY_CODE_5, TOTP_RECOVERY_CODE_6)));

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

    Set<IamTotpRecoveryCode> newCodes = new HashSet<>();
    for (IamTotpRecoveryCode recoveryCode : totpMfa.getRecoveryCodes()) {
      IamTotpRecoveryCode newCode = new IamTotpRecoveryCode(newTotpMfa);
      newCode.setCode(recoveryCode.getCode());
      newCodes.add(newCode);
    }
    newTotpMfa.setRecoveryCodes(newCodes);

    newTotpMfa.touch();

    return newTotpMfa;
  }
}
