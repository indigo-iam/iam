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
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;

public class MultiFactorTestSupport {
  public static final String TEST_USERNAME = "test-pre-authenticated-user";
  public static final String TEST_UUID = "ceb173b4-28e3-43ad-aaf7-15d3730e2b90";
  public static final String TEST_EMAIL = "test@example.org";
  public static final String TEST_GIVEN_NAME = "Test";
  public static final String TEST_FAMILY_NAME = "User";
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

  protected final IamAccount TEST_ACCOUNT;
  protected final IamTotpMfa TOTP_MFA;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_1;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_2;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_3;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_4;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_5;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_6;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_7;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_8;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_9;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_10;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_11;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_12;

  protected final Set<IamTotpRecoveryCode> RECOVERY_CODE_SET_FIRST;
  protected final Set<IamTotpRecoveryCode> RECOVERY_CODE_SET_SECOND;

  public MultiFactorTestSupport() {
    TOTP_MFA = new IamTotpMfa();
    TOTP_MFA.setSecret(TOTP_MFA_SECRET);
    TOTP_MFA.setActive(true);

    TOTP_RECOVERY_CODE_1 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_2 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_3 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_4 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_5 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_6 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_7 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_8 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_9 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_10 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_11 = new IamTotpRecoveryCode(TOTP_MFA);
    TOTP_RECOVERY_CODE_12 = new IamTotpRecoveryCode(TOTP_MFA);

    TOTP_RECOVERY_CODE_1.setCode(TOTP_RECOVERY_CODE_STRING_1);
    TOTP_RECOVERY_CODE_2.setCode(TOTP_RECOVERY_CODE_STRING_2);
    TOTP_RECOVERY_CODE_3.setCode(TOTP_RECOVERY_CODE_STRING_3);
    TOTP_RECOVERY_CODE_4.setCode(TOTP_RECOVERY_CODE_STRING_4);
    TOTP_RECOVERY_CODE_5.setCode(TOTP_RECOVERY_CODE_STRING_5);
    TOTP_RECOVERY_CODE_6.setCode(TOTP_RECOVERY_CODE_STRING_6);
    TOTP_RECOVERY_CODE_7.setCode(TOTP_RECOVERY_CODE_STRING_7);
    TOTP_RECOVERY_CODE_8.setCode(TOTP_RECOVERY_CODE_STRING_8);
    TOTP_RECOVERY_CODE_9.setCode(TOTP_RECOVERY_CODE_STRING_9);
    TOTP_RECOVERY_CODE_10.setCode(TOTP_RECOVERY_CODE_STRING_10);
    TOTP_RECOVERY_CODE_11.setCode(TOTP_RECOVERY_CODE_STRING_11);
    TOTP_RECOVERY_CODE_12.setCode(TOTP_RECOVERY_CODE_STRING_12);

    RECOVERY_CODE_SET_FIRST = new HashSet<>(
        Arrays.asList(TOTP_RECOVERY_CODE_1, TOTP_RECOVERY_CODE_2, TOTP_RECOVERY_CODE_3,
            TOTP_RECOVERY_CODE_4, TOTP_RECOVERY_CODE_5, TOTP_RECOVERY_CODE_6));
    RECOVERY_CODE_SET_SECOND = new HashSet<>(
        Arrays.asList(TOTP_RECOVERY_CODE_7, TOTP_RECOVERY_CODE_8, TOTP_RECOVERY_CODE_9,
            TOTP_RECOVERY_CODE_10, TOTP_RECOVERY_CODE_11, TOTP_RECOVERY_CODE_12));

    TOTP_MFA.setRecoveryCodes(RECOVERY_CODE_SET_FIRST);
    TEST_ACCOUNT = IamAccount.newAccount();
    TEST_ACCOUNT.setUsername(TEST_USERNAME);
    TEST_ACCOUNT.setUuid(TEST_UUID);
    TEST_ACCOUNT.getUserInfo().setEmail(TEST_EMAIL);
    TEST_ACCOUNT.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    TEST_ACCOUNT.getUserInfo().setFamilyName(TEST_FAMILY_NAME);
    TEST_ACCOUNT.setTotpMfa(TOTP_MFA);

    TEST_ACCOUNT.touch();
  }

  protected void resetTestAccount() {
    TOTP_MFA.setSecret(TOTP_MFA_SECRET);
    TOTP_MFA.setActive(true);

    TOTP_RECOVERY_CODE_1.setCode(TOTP_RECOVERY_CODE_STRING_1);
    TOTP_RECOVERY_CODE_2.setCode(TOTP_RECOVERY_CODE_STRING_2);
    TOTP_RECOVERY_CODE_3.setCode(TOTP_RECOVERY_CODE_STRING_3);
    TOTP_RECOVERY_CODE_4.setCode(TOTP_RECOVERY_CODE_STRING_4);
    TOTP_RECOVERY_CODE_5.setCode(TOTP_RECOVERY_CODE_STRING_5);
    TOTP_RECOVERY_CODE_6.setCode(TOTP_RECOVERY_CODE_STRING_6);
    TOTP_RECOVERY_CODE_7.setCode(TOTP_RECOVERY_CODE_STRING_7);
    TOTP_RECOVERY_CODE_8.setCode(TOTP_RECOVERY_CODE_STRING_8);
    TOTP_RECOVERY_CODE_9.setCode(TOTP_RECOVERY_CODE_STRING_9);
    TOTP_RECOVERY_CODE_10.setCode(TOTP_RECOVERY_CODE_STRING_10);
    TOTP_RECOVERY_CODE_11.setCode(TOTP_RECOVERY_CODE_STRING_11);
    TOTP_RECOVERY_CODE_12.setCode(TOTP_RECOVERY_CODE_STRING_12);

    TOTP_MFA.setRecoveryCodes(RECOVERY_CODE_SET_FIRST);

    TEST_ACCOUNT.setUsername(TEST_USERNAME);
    TEST_ACCOUNT.setUuid(TEST_UUID);
    TEST_ACCOUNT.getUserInfo().setEmail(TEST_EMAIL);
    TEST_ACCOUNT.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    TEST_ACCOUNT.getUserInfo().setFamilyName(TEST_FAMILY_NAME);
    TEST_ACCOUNT.setTotpMfa(TOTP_MFA);

    TEST_ACCOUNT.touch();
  }

  protected IamAccount cloneAccount(IamAccount account) {
    IamAccount newAccount = IamAccount.newAccount();
    newAccount.setUuid(account.getUuid());
    newAccount.setUsername(account.getUsername());
    newAccount.getUserInfo().setEmail(account.getUserInfo().getEmail());
    newAccount.getUserInfo().setGivenName(account.getUserInfo().getGivenName());
    newAccount.getUserInfo().setFamilyName(account.getUserInfo().getFamilyName());

    IamTotpMfa totpMfa = new IamTotpMfa();
    Set<IamTotpRecoveryCode> newCodes = new HashSet<>();
    for (IamTotpRecoveryCode recoveryCode : account.getTotpMfa().getRecoveryCodes()) {
      IamTotpRecoveryCode newCode = new IamTotpRecoveryCode(totpMfa);
      newCode.setCode(recoveryCode.getCode());
      newCodes.add(newCode);
    }
    totpMfa.setRecoveryCodes(newCodes);
    newAccount.setTotpMfa(totpMfa);

    newAccount.touch();

    return newAccount;
  }
}
