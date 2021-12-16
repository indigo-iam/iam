package it.infn.mw.iam.test.multi_factor_authentication;

import java.util.Arrays;
import java.util.HashSet;

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

  protected final IamAccount TEST_ACCOUNT;
  protected final IamTotpMfa TOTP_MFA;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_1;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_2;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_3;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_4;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_5;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_6;

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

    TOTP_RECOVERY_CODE_1.setCode(TOTP_RECOVERY_CODE_STRING_1);
    TOTP_RECOVERY_CODE_2.setCode(TOTP_RECOVERY_CODE_STRING_2);
    TOTP_RECOVERY_CODE_3.setCode(TOTP_RECOVERY_CODE_STRING_3);
    TOTP_RECOVERY_CODE_4.setCode(TOTP_RECOVERY_CODE_STRING_4);
    TOTP_RECOVERY_CODE_5.setCode(TOTP_RECOVERY_CODE_STRING_5);
    TOTP_RECOVERY_CODE_6.setCode(TOTP_RECOVERY_CODE_STRING_6);

    TOTP_MFA
      .setRecoveryCodes(new HashSet<>(Arrays.asList(TOTP_RECOVERY_CODE_1, TOTP_RECOVERY_CODE_2,
          TOTP_RECOVERY_CODE_3, TOTP_RECOVERY_CODE_4, TOTP_RECOVERY_CODE_5, TOTP_RECOVERY_CODE_6)));
    TEST_ACCOUNT = IamAccount.newAccount();
    TEST_ACCOUNT.setUsername(TEST_USERNAME);
    TEST_ACCOUNT.setUuid(TEST_UUID);
    TEST_ACCOUNT.getUserInfo().setEmail(TEST_EMAIL);
    TEST_ACCOUNT.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    TEST_ACCOUNT.getUserInfo().setFamilyName(TEST_FAMILY_NAME);
    TEST_ACCOUNT.setTotpMfa(TOTP_MFA);

    TEST_ACCOUNT.touch();
  }
}
