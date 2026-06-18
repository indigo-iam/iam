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

import java.time.Instant;
import java.util.Date;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

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

  public static final String TOTP_USERNAME = "test-mfa-user";
  public static final String TOTP_UUID = "ceb173b4-28e3-43ad-aaf7-15d3730e2b90";
  public static final String TOTP_EMAIL = "test-mfa@example.org";
  public static final String TOTP_GIVEN_NAME = "Test";
  public static final String TOTP_FAMILY_NAME = "Mfa";
  public static final String KEY_TO_ENCRYPT_DECRYPT = "define_me_please";
  public static final String TOTP_MFA_SECRET = "secret";

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

  protected static final IamAuthority ROLE_USER_AUTHORITY;

  protected static final IamSamlId TEST_SAML_ID;
  protected static final IamOidcId TEST_OIDC_ID;

  static {

    ROLE_USER_AUTHORITY = new IamAuthority("ROLE_USER");

    TEST_SAML_ID =
        new IamSamlId(TEST_SAML_ID_IDP_ID, TEST_SAML_ID_ATTRIBUTE_ID, TEST_SAML_ID_USER_ID);

    TEST_OIDC_ID = new IamOidcId(TEST_OIDC_ID_ISSUER, TEST_OIDC_ID_SUBJECT);
  }

  protected IamX509Certificate getTestX509Certificate1() {

    IamX509Certificate c = new IamX509Certificate();
    c.setLabel(TEST_X509_CERTIFICATE_LABEL_1);
    c.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    c.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    c.setCertificate(TEST_X509_CERTIFICATE_VALUE_1);
    c.setPrimary(false);
    return c;
  }

  protected IamX509Certificate getTestX509Certificate2() {

    IamX509Certificate c = new IamX509Certificate();
    c.setLabel(TEST_X509_CERTIFICATE_LABEL_2);
    c.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_2);
    c.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_2);
    c.setCertificate(TEST_X509_CERTIFICATE_VALUE_2);
    c.setPrimary(false);
    return c;
  }

  protected IamSshKey getTestSshKey1(Instant instant) {
    IamSshKey k = new IamSshKey(TEST_SSH_KEY_VALUE_1);
    k.setCreationTime(Date.from(instant));
    k.setPrimary(false);
    return k;
  }

  protected IamSshKey getTestSshKey2(Instant instant) {
    IamSshKey k = new IamSshKey(TEST_SSH_KEY_VALUE_2);
    k.setCreationTime(Date.from(instant));
    k.setPrimary(false);
    return k;
  }

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

  protected IamAccount getCiccioAccount(Instant instant) {
    IamAccount a = IamAccount.newAccount();
    a.setUsername(CICCIO_USERNAME);
    a.setUuid(CICCIO_UUID);
    a.getUserInfo().setEmail(CICCIO_EMAIL);
    a.getUserInfo().setGivenName(CICCIO_GIVEN_NAME);
    a.getUserInfo().setFamilyName(CICCIO_FAMILY_NAME);
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
