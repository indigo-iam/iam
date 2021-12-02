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
package it.infn.mw.iam.test.service;

import java.util.Arrays;
import java.util.HashSet;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

public class IamAccountServiceTestSupport {

  public static final String PASSWORD = "password";

  public static final String TEST_UUID = "ceb173b4-28e3-43ad-aaf7-15d3730e2b90";
  public static final String TEST_USERNAME = "test";
  public static final String TEST_EMAIL = "test@example.org";
  public static final String TEST_GIVEN_NAME = "Test";
  public static final String TEST_FAMILY_NAME = "User";

  public static final String CICCIO_UUID = "96294e50-fe83-4136-a77a-065e4368c421";
  public static final String CICCIO_USERNAME = "ciccio";
  public static final String CICCIO_EMAIL = "ciccio@example.org";
  public static final String CICCIO_GIVEN_NAME = "Ciccio";
  public static final String CICCIO_FAMILY_NAME = "Paglia";

  public static final String TOTP_MFA_ACCOUNT_UUID = "b3e7dd7f-a1ac-eda0-371d-b902a6c5cee2";
  public static final String TOTP_MFA_ACCOUNT_USERNAME = "totp";
  public static final String TOTP_MFA_ACCOUNT_EMAIL = "totp@example.org";
  public static final String TOTP_MFA_ACCOUNT_GIVEN_NAME = "Totp";
  public static final String TOTP_MFA_ACCOUNT_FAMILY_NAME = "Mfa";

  public static final String TEST_SAML_ID_IDP_ID = "idpId";
  public static final String TEST_SAML_ID_USER_ID = "userId";
  public static final String TEST_SAML_ID_ATTRIBUTE_ID = "attributeId";

  public static final String TEST_OIDC_ID_ISSUER = "oidcIssuer";
  public static final String TEST_OIDC_ID_SUBJECT = "oidcSubject";

  public static final String TEST_SSH_KEY_VALUE_1 = "ssh-key-value-1";
  public static final String TEST_SSH_KEY_VALUE_2 = "ssh-key-value-2";

  public static final String TEST_X509_CERTIFICATE_VALUE_1 = "x509-cert-value-1";
  public static final String TEST_X509_CERTIFICATE_SUBJECT_1 = "x509-cert-subject-1";
  public static final String TEST_X509_CERTIFICATE_ISSUER_1 = "x509-cert-issuer-1";
  public static final String TEST_X509_CERTIFICATE_LABEL_1 = "x509-cert-label-1";

  public static final String TEST_X509_CERTIFICATE_VALUE_2 = "x509-cert-value-2";
  public static final String TEST_X509_CERTIFICATE_SUBJECT_2 = "x509-cert-subject-2";
  public static final String TEST_X509_CERTIFICATE_ISSUER_2 = "x509-cert-issuer-2";
  public static final String TEST_X509_CERTIFICATE_LABEL_2 = "x509-cert-label-2";

  public static final String TOTP_MFA_SECRET = "secret";

  public static final String TOTP_RECOVERY_CODE_STRING_1 = "code-1";
  public static final String TOTP_RECOVERY_CODE_STRING_2 = "code-2";
  public static final String TOTP_RECOVERY_CODE_STRING_3 = "code-3";
  public static final String TOTP_RECOVERY_CODE_STRING_4 = "code-4";
  public static final String TOTP_RECOVERY_CODE_STRING_5 = "code-5";
  public static final String TOTP_RECOVERY_CODE_STRING_6 = "code-6";


  protected final IamAccount TEST_ACCOUNT;
  protected final IamAccount CICCIO_ACCOUNT;
  protected final IamAccount TOTP_MFA_ACCOUNT;
  protected final IamAuthority ROLE_USER_AUTHORITY;
  protected final IamSamlId TEST_SAML_ID;
  protected final IamOidcId TEST_OIDC_ID;

  protected final IamSshKey TEST_SSH_KEY_1;
  protected final IamSshKey TEST_SSH_KEY_2;
  protected final IamX509Certificate TEST_X509_CERTIFICATE_1;
  protected final IamX509Certificate TEST_X509_CERTIFICATE_2;

  protected final IamTotpMfa TOTP_MFA;

  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_1;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_2;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_3;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_4;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_5;
  protected final IamTotpRecoveryCode TOTP_RECOVERY_CODE_6;

  public IamAccountServiceTestSupport() {
    TEST_ACCOUNT = IamAccount.newAccount();
    TEST_ACCOUNT.setUuid(TEST_UUID);
    TEST_ACCOUNT.setUsername(TEST_USERNAME);
    TEST_ACCOUNT.getUserInfo().setEmail(TEST_EMAIL);
    TEST_ACCOUNT.getUserInfo().setGivenName(TEST_GIVEN_NAME);
    TEST_ACCOUNT.getUserInfo().setFamilyName(TEST_FAMILY_NAME);

    ROLE_USER_AUTHORITY = new IamAuthority("ROLE_USER");

    CICCIO_ACCOUNT = IamAccount.newAccount();
    CICCIO_ACCOUNT.setUuid(CICCIO_UUID);
    CICCIO_ACCOUNT.setUsername(CICCIO_USERNAME);
    CICCIO_ACCOUNT.getUserInfo().setEmail(CICCIO_EMAIL);
    CICCIO_ACCOUNT.getUserInfo().setGivenName(CICCIO_GIVEN_NAME);
    CICCIO_ACCOUNT.getUserInfo().setFamilyName(CICCIO_FAMILY_NAME);

    TEST_SAML_ID =
        new IamSamlId(TEST_SAML_ID_IDP_ID, TEST_SAML_ID_ATTRIBUTE_ID, TEST_SAML_ID_USER_ID);

    TEST_OIDC_ID = new IamOidcId(TEST_OIDC_ID_ISSUER, TEST_OIDC_ID_SUBJECT);

    TEST_SSH_KEY_1 = new IamSshKey(TEST_SSH_KEY_VALUE_1);

    TEST_SSH_KEY_2 = new IamSshKey(TEST_SSH_KEY_VALUE_2);

    TEST_X509_CERTIFICATE_1 = new IamX509Certificate();

    TEST_X509_CERTIFICATE_1.setLabel(TEST_X509_CERTIFICATE_LABEL_1);
    TEST_X509_CERTIFICATE_1.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    TEST_X509_CERTIFICATE_1.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    TEST_X509_CERTIFICATE_1.setCertificate(TEST_X509_CERTIFICATE_VALUE_1);

    TEST_X509_CERTIFICATE_2 = new IamX509Certificate();

    TEST_X509_CERTIFICATE_2.setLabel(TEST_X509_CERTIFICATE_LABEL_2);
    TEST_X509_CERTIFICATE_2.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_2);
    TEST_X509_CERTIFICATE_2.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_2);
    TEST_X509_CERTIFICATE_2.setCertificate(TEST_X509_CERTIFICATE_VALUE_2);

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

    TOTP_MFA_ACCOUNT = IamAccount.newAccount();
    TOTP_MFA_ACCOUNT.setUuid(TOTP_MFA_ACCOUNT_UUID);
    TOTP_MFA_ACCOUNT.setUsername(TOTP_MFA_ACCOUNT_USERNAME);
    TOTP_MFA_ACCOUNT.getUserInfo().setEmail(TOTP_MFA_ACCOUNT_EMAIL);
    TOTP_MFA_ACCOUNT.getUserInfo().setGivenName(TOTP_MFA_ACCOUNT_GIVEN_NAME);
    TOTP_MFA_ACCOUNT.getUserInfo().setFamilyName(TOTP_MFA_ACCOUNT_FAMILY_NAME);
    TOTP_MFA_ACCOUNT.setTotpMfa(TOTP_MFA);
  }

  public IamAccount cloneAccount(IamAccount account) {
    IamAccount newAccount = IamAccount.newAccount();
    newAccount.setUuid(account.getUuid());
    newAccount.setUsername(account.getUsername());
    newAccount.getUserInfo().setEmail(account.getUserInfo().getEmail());
    newAccount.getUserInfo().setGivenName(account.getUserInfo().getGivenName());
    newAccount.getUserInfo().setFamilyName(account.getUserInfo().getFamilyName());
    newAccount.setTotpMfa(account.getTotpMfa());

    return newAccount;
  }


}
