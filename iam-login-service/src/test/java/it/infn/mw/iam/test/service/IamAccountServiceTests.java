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

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.audit.events.account.AccountEndTimeUpdatedEvent;
import it.infn.mw.iam.audit.events.account.EmailReplacedEvent;
import it.infn.mw.iam.audit.events.account.FamilyNameReplacedEvent;
import it.infn.mw.iam.audit.events.account.GivenNameReplacedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DefaultGroup;
import it.infn.mw.iam.core.group.DefaultIamGroupService;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.core.user.DefaultIamAccountService;
import it.infn.mw.iam.core.user.exception.CredentialAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.EmailAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.InvalidCredentialException;
import it.infn.mw.iam.core.user.exception.UserAlreadyExistsException;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.registration.TokenGenerator;

@ExtendWith(MockitoExtension.class)
class IamAccountServiceTests extends IamAccountServiceTestSupport {

  static final String TEST_GROUP_1 = "Test-group-1";

  static final Instant NOW = Instant.parse("2021-01-01T00:00:00.00Z");

  @Mock
  IamAccountRepository accountRepo;

  @Mock
  IamGroupRepository groupRepo;

  @Mock
  IamAuthoritiesRepository authoritiesRepo;

  @Mock
  IamAccountClientRepository accountClientRepo;

  @Mock
  IamAupSignatureRepository aupSignatureRepo;

  @Mock
  PasswordEncoder passwordEncoder;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  TimeProvider timeProvider;

  @Mock
  TokenRevocationService tokenRevocationService;

  @Mock
  NotificationFactory notificationFactory;

  @Mock
  DefaultIamGroupService iamGroupService;

  @Mock
  TokenGenerator tokenGenerator;

  @Mock
  IamTotpMfaRepository iamTotpMfaRepository;

  @Mock
  IamProperties iamProperties;

  IamProperties.RegistrationProperties registrationProperties =
      new IamProperties.RegistrationProperties();

  Clock clock = Clock.fixed(NOW, ZoneId.of("UTC"));

  DefaultIamAccountService accountService;

  @Captor
  ArgumentCaptor<ApplicationEvent> eventCaptor;

  IamAccount testAccount;
  IamAccount ciccioAccount;
  IamAccount mfaAccount;
  IamTotpMfa totpMfa;
  IamX509Certificate x509Certificate1;
  IamX509Certificate x509Certificate2;
  IamSshKey sshKey1;
  IamSshKey sshKey2;

  @BeforeEach
  void setup() {

    testAccount = getTestAccount(clock.instant());
    ciccioAccount = getCiccioAccount(clock.instant());
    mfaAccount = getTotpMfaAccount(clock.instant());
    totpMfa = getTotpMfaFor(mfaAccount, clock.instant());
    x509Certificate1 = getTestX509Certificate1();
    x509Certificate2 = getTestX509Certificate2();
    sshKey1 = getTestSshKey1(clock.instant());
    sshKey2 = getTestSshKey2(clock.instant());

    lenient().when(accountRepo.findByCertificateSubject(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findBySshKeyValue(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findBySamlId(any())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByUsername(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByEmail(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testAccount));
    lenient().when(accountRepo.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(testAccount));
    lenient().when(accountRepo.findByEmailWithDifferentUUID(TEST_EMAIL, CICCIO_UUID))
      .thenThrow(EmailAlreadyBoundException.class);
    lenient().when(authoritiesRepo.findByAuthority(anyString())).thenReturn(Optional.empty());
    lenient().when(authoritiesRepo.findByAuthority("ROLE_USER"))
      .thenReturn(Optional.of(ROLE_USER_AUTHORITY));
    lenient().when(passwordEncoder.encode(any())).thenReturn(PASSWORD);
    lenient().when(iamProperties.getRegistration()).thenReturn(registrationProperties);

    accountService = new DefaultIamAccountService(clock, accountRepo, groupRepo, authoritiesRepo,
        passwordEncoder, eventPublisher, tokenRevocationService, accountClientRepo,
        notificationFactory, iamProperties, iamGroupService, tokenGenerator, aupSignatureRepo,
        iamTotpMfaRepository);
  }

  @Test
  void testCreateNullAccountFails() {

    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(null));
    assertThat(e.getMessage(), equalTo("Cannot create a null account"));
  }

  @Test
  void testNullUsernameFails() {

    IamAccount account = IamAccount.newAccount();
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("Null or empty username"));
  }

  @Test
  void testEmptyUsernameFails() {

    IamAccount account = IamAccount.newAccount();
    account.setUsername("");
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("Null or empty username"));
  }

  @Test
  void testNullUserinfoFails() {

    IamAccount account = new IamAccount();
    account.setUsername("test");
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("Null userinfo object"));
  }

  @Test
  void testNullEmailFails() {

    IamAccount account = IamAccount.newAccount();
    account.setUsername("test");

    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("Null or empty email"));
  }

  @Test
  void testEmptyEmailFails() {

    IamAccount account = IamAccount.newAccount();
    account.setUsername("test");
    account.getUserInfo().setEmail("");

    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("Null or empty email"));
  }

  @Test
  void testBoundUsernameChecksWorks() {

    IamAccount account = IamAccount.newAccount();
    account.setUsername(TEST_USERNAME);
    account.getUserInfo().setEmail("cicciopaglia@test.org");

    UserAlreadyExistsException e =
        assertThrows(UserAlreadyExistsException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(),
        equalTo(String.format("A user with username '%s' already exists", TEST_USERNAME)));
  }

  @Test
  void testBoundEmailCheckWorks() {

    IamAccount account = IamAccount.newAccount();
    account.setUsername("ciccio");
    account.getUserInfo().setEmail(TEST_EMAIL);

    UserAlreadyExistsException e =
        assertThrows(UserAlreadyExistsException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(),
        equalTo(String.format("A user linked with email '%s' already exists", TEST_EMAIL)));
  }

  @Test
  void testCreationFailsIfRoleUserAuthorityIsNotDefined() {

    Mockito.when(authoritiesRepo.findByAuthority("ROLE_USER")).thenReturn(Optional.empty());

    IllegalStateException e = assertThrows(IllegalStateException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("ROLE_USER not found in database. This is a bug"));
  }


  @Test
  void testUuidIfProvidedIsPreserved() {

    accountService.createAccount(ciccioAccount);
    Mockito.verify(accountRepo, Mockito.times(1)).save(ciccioAccount);
    assertThat(ciccioAccount.getUuid(), equalTo(CICCIO_UUID));

  }

  @Test
  void testUuidIfNotProvidedIsGenerated() {

    ciccioAccount.setUuid(null);

    accountService.createAccount(ciccioAccount);
    Mockito.verify(accountRepo, Mockito.times(1)).save(ciccioAccount);
    assertNotNull(ciccioAccount.getUuid());
  }

  @Test
  void testCreationTimeIfProvidedIsPreserved() {

    Date yesterday = Date.from(clock.instant().minus(Duration.ofDays(1)));

    ciccioAccount.setCreationTime(yesterday);
    accountService.createAccount(ciccioAccount);
    Mockito.verify(accountRepo, times(1)).save(ciccioAccount);
    assertThat(ciccioAccount.getCreationTime(), equalTo(yesterday));
  }

  @Test
  void testPasswordIfProvidedIsPreservedAndEncoded() {

    ciccioAccount.setPassword(PASSWORD);

    accountService.createAccount(ciccioAccount);
    Mockito.verify(accountRepo, Mockito.times(1)).save(ciccioAccount);
    Mockito.verify(passwordEncoder, Mockito.times(1)).encode(PASSWORD);

    assertThat(ciccioAccount.getPassword(), equalTo(PASSWORD));
  }

  @Test
  void testNullSamlIdIsNotAccepted() {

    ciccioAccount.getSamlIds().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null saml id"));
  }

  @Test
  void testNullSamlIdpIdIsNotAccepted() {

    IamSamlId samlId = new IamSamlId();
    ciccioAccount.linkSamlIds(asList(samlId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty idpId"));
  }

  @Test
  void testEmptySamlIdpIdIsNotAccepted() {

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId("");
    ciccioAccount.linkSamlIds(asList(samlId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty idpId"));
  }

  @Test
  void testNullSamlUserIdIsNotAccepted() {
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);

    ciccioAccount.linkSamlIds(asList(samlId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty userId"));
  }

  @Test
  void testEmptySamlUserIdIsNotAccepted() {

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId("");

    ciccioAccount.linkSamlIds(asList(samlId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty userId"));
  }

  @Test
  void testNullSamlAttributeIdIsNotAccepted() {

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId(TEST_SAML_ID_USER_ID);

    ciccioAccount.linkSamlIds(asList(samlId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty attributeId"));
  }

  @Test
  void testEmptySamlAttributeIdIsNotAccepted() {

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId(TEST_SAML_ID_USER_ID);
    samlId.setAttributeId("");

    ciccioAccount.linkSamlIds(asList(samlId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty attributeId"));
  }

  @Test
  void testBoundSamlIdIsNotAccepted() {

    Mockito.when(accountRepo.findBySamlId(TEST_SAML_ID)).thenReturn(Optional.of(ciccioAccount));
    ciccioAccount.linkSamlIds(asList(TEST_SAML_ID));
    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testValidSamlIdLinkedPassesSanityChecks() {

    ciccioAccount.linkSamlIds(asList(TEST_SAML_ID));
    assertDoesNotThrow(() -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testNullOidcIdIsNotAccepted() {

    ciccioAccount.getOidcIds().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null oidc id"));
  }

  @Test
  void testNullOidcIdIssuerIsNotAccepted() {

    IamOidcId oidcId = new IamOidcId();
    ciccioAccount.linkOidcIds(asList(oidcId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty oidc id issuer"));
  }

  @Test
  void testEmptyOidcIdIssuerIsNotAccepted() {

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer("");
    ciccioAccount.linkOidcIds(asList(oidcId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty oidc id issuer"));
  }

  @Test
  void testNullOidcIdSubjectIsNotAccepted() {

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(TEST_OIDC_ID_ISSUER);
    ciccioAccount.linkOidcIds(asList(oidcId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty oidc id subject"));
  }

  @Test
  void testEmptyOidcIdSubjectIsNotAccepted() {

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(TEST_OIDC_ID_ISSUER);
    oidcId.setSubject("");
    ciccioAccount.linkOidcIds(asList(oidcId));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty oidc id subject"));
  }

  @Test
  void testBoundOidcIdIsNotAccepted() {

    Mockito.when(accountRepo.findByOidcId(TEST_OIDC_ID_ISSUER, TEST_OIDC_ID_SUBJECT))
      .thenReturn(Optional.of(ciccioAccount));

    ciccioAccount.linkOidcIds(asList(TEST_OIDC_ID));
    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testValidOidcIdPassesSanityChecks() {

    ciccioAccount.linkOidcIds(asList(TEST_OIDC_ID));
    assertDoesNotThrow(() -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testNullSshKeyIsNotAccepted() {

    ciccioAccount.getSshKeys().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null ssh key"));
  }

  @Test
  void testNoValueSshKeyIsNotAccepted() {

    IamSshKey key = new IamSshKey();
    ciccioAccount.linkSshKeys(asList(key));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty ssh key value"));
  }

  @Test
  void testEmptyValueSshKeyIsNotAccepted() {

    IamSshKey key = new IamSshKey();
    key.setValue("");
    ciccioAccount.linkSshKeys(asList(key));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty ssh key value"));
  }

  @Test
  void testBoundSshKeyIsNotAccepted() {

    ciccioAccount.linkSshKeys(asList(sshKey1));
    Mockito.when(accountRepo.findBySshKeyValue(TEST_SSH_KEY_VALUE_1))
      .thenReturn(Optional.of(ciccioAccount));
    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testValidSshKeyPassesSanityChecks() {

    ciccioAccount.linkSshKeys(asList(sshKey1));
    assertDoesNotThrow(() -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testNullX509CertificateIsNotAccepted() {

    ciccioAccount.getX509Certificates().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null X.509 certificate"));
  }

  @Test
  void testNullX509CertificateSubjectIsNotAccepted() {

    IamX509Certificate cert = new IamX509Certificate();
    ciccioAccount.linkX509Certificates(asList(cert));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate subject DN"));
  }

  @Test
  void testNullX509CertificateIssuerIsNotAccepted() {

    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    ciccioAccount.linkX509Certificates(asList(cert));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate issuer DN"));
  }

  @Test
  void testNullX509CertificateLabelIsNotAccepted() {

    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    cert.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    ciccioAccount.linkX509Certificates(asList(cert));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate label"));
  }

  @Test
  void testEmptyX509CertificateLabelIsNotAccepted() {

    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    cert.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    cert.setLabel("");
    ciccioAccount.linkX509Certificates(asList(cert));
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate label"));
  }

  @Test
  void testBoundX509CertificateIsNotAccepted() {

    ciccioAccount.linkX509Certificates(asList(x509Certificate1));

    lenient().when(accountRepo.findByCertificateSubject(TEST_X509_CERTIFICATE_SUBJECT_1))
      .thenReturn(Optional.of(ciccioAccount));

    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testValidX509CertificatePassesSanityChecks() {

    ciccioAccount.linkX509Certificates(asList(getTestX509Certificate2()));
    assertDoesNotThrow(() -> accountService.createAccount(ciccioAccount));
  }

  @Test
  void testX509PrimaryIsBoundIfNotProvided() {

    ciccioAccount.linkX509Certificates(asList(x509Certificate1, x509Certificate2));
    accountService.createAccount(ciccioAccount);

    for (IamX509Certificate cert : ciccioAccount.getX509Certificates()) {
      if (cert.getSubjectDn().equals(TEST_X509_CERTIFICATE_SUBJECT_1)) {
        assertTrue(cert.isPrimary());
      }

      if (cert.getSubjectDn().equals(TEST_X509_CERTIFICATE_SUBJECT_2)) {
        assertFalse(cert.isPrimary());
      }
    }
  }

  @Test
  void testX509PrimaryIsRespected() {

    x509Certificate2.setPrimary(true);
    ciccioAccount.linkX509Certificates(asList(x509Certificate1, x509Certificate2));
    accountService.createAccount(ciccioAccount);

    for (IamX509Certificate cert : ciccioAccount.getX509Certificates()) {
      if (cert.getSubjectDn().equals(TEST_X509_CERTIFICATE_SUBJECT_1)) {
        assertFalse(cert.isPrimary());
      }
      if (cert.getSubjectDn().equals(TEST_X509_CERTIFICATE_SUBJECT_2)) {
        assertTrue(cert.isPrimary());
      }
    }
  }

  @Test
  void testX509MultiplePrimaryIsNotAccepted() {

    x509Certificate1.setPrimary(true);
    x509Certificate2.setPrimary(true);
    ciccioAccount.linkX509Certificates(asList(x509Certificate1, x509Certificate2));
    InvalidCredentialException e = assertThrows(InvalidCredentialException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("Only one X.509 certificate can be marked as primary"));
  }

  @Test
  void testSshKeyPrimaryIsBoundIfNotProvided() {

    ciccioAccount.linkSshKeys(asList(sshKey1, sshKey2));
    accountService.createAccount(ciccioAccount);

    for (IamSshKey key : ciccioAccount.getSshKeys()) {
      if (key.getValue().equals(sshKey1.getValue())) {
        assertTrue(key.isPrimary());
      }
      if (key.getValue().equals(sshKey2.getValue())) {
        assertFalse(key.isPrimary());
      }
    }
  }

  @Test
  void testSshKeyPrimaryIsRespected() {

    sshKey2.setPrimary(true);
    ciccioAccount.linkSshKeys(asList(sshKey1, sshKey2));
    accountService.createAccount(ciccioAccount);

    for (IamSshKey key : ciccioAccount.getSshKeys()) {
      if (key.getValue().equals(sshKey1.getValue())) {
        assertFalse(key.isPrimary());
      }
      if (key.getValue().equals(sshKey2.getValue())) {
        assertTrue(key.isPrimary());
      }
    }
  }

  @Test
  void testMultiplePrimarySshKeysIsNotAccepted() {

    sshKey1.setPrimary(true);
    sshKey2.setPrimary(true);
    ciccioAccount.linkSshKeys(asList(sshKey1, sshKey2));
    InvalidCredentialException e = assertThrows(InvalidCredentialException.class,
        () -> accountService.createAccount(ciccioAccount));
    assertThat(e.getMessage(), equalTo("Only one SSH key can be marked as primary"));
  }

  @Test
  void testNullDeleteAccountFails() {

    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.deleteAccount(null));
    assertThat(e.getMessage(), equalTo("cannot delete a null account"));
  }

  @Test
  void testAccountDeletion() {

    accountService.deleteAccount(ciccioAccount);

    Mockito.verify(accountRepo, times(1)).delete(ciccioAccount);
    Mockito.verify(eventPublisher, times(1)).publishEvent(any());
  }

  @Test
  void testMfaRemovedWhenAccountRemoved() {

    Mockito.when(iamTotpMfaRepository.findByAccount(mfaAccount)).thenReturn(Optional.of(totpMfa));

    accountService.deleteAccount(mfaAccount);

    Mockito.verify(iamTotpMfaRepository, times(1)).delete(totpMfa);
    Mockito.verify(accountRepo, times(1)).delete(mfaAccount);
  }

  @Test
  void testSetEndTimeRequiresNonNullAccount() {

    NullPointerException e = assertThrows(NullPointerException.class,
        () -> accountService.setAccountEndTime(null, null));
    assertThat(e.getMessage(), containsString("Cannot set endTime on a null account"));
  }

  @Test
  void testSetSameGivenName() {

    assertThat(ciccioAccount.getUserInfo().getGivenName(), is("Ciccio"));
    accountService.setAccountGivenName(ciccioAccount, "Ciccio");
    Mockito.verify(accountRepo, times(0)).save(ciccioAccount);
    Mockito.verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetNewGivenName() {

    assertThat(ciccioAccount.getUserInfo().getGivenName(), is("Ciccio"));
    accountService.setAccountGivenName(ciccioAccount, "Pasticcio");
    Mockito.verify(accountRepo, times(1)).save(ciccioAccount);
    Mockito.verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(GivenNameReplacedEvent.class));
    GivenNameReplacedEvent e = (GivenNameReplacedEvent) event;
    assertThat(e.getGivenName(), is("Pasticcio"));
    assertThat(e.getAccount().getUserInfo().getGivenName(), is("Pasticcio"));
  }

  @Test
  void testSetNullGivenName() {

    assertThat(ciccioAccount.getUserInfo().getGivenName(), is("Ciccio"));
    accountService.setAccountGivenName(ciccioAccount, null);
    Mockito.verify(accountRepo, times(1)).save(ciccioAccount);
    Mockito.verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(GivenNameReplacedEvent.class));
    GivenNameReplacedEvent e = (GivenNameReplacedEvent) event;
    assertThat(e.getGivenName(), nullValue());
    assertThat(e.getAccount().getUserInfo().getGivenName(), nullValue());

    accountService.setAccountGivenName(ciccioAccount, null);
    Mockito.verify(accountRepo, times(1)).save(ciccioAccount);
    Mockito.verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetSameFamilyName() {

    assertThat(ciccioAccount.getUserInfo().getFamilyName(), is("Paglia"));
    accountService.setAccountFamilyName(ciccioAccount, "Paglia");
    Mockito.verify(accountRepo, times(0)).save(ciccioAccount);
    Mockito.verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetNewFamilyName() {

    assertThat(ciccioAccount.getUserInfo().getFamilyName(), is("Paglia"));
    accountService.setAccountFamilyName(ciccioAccount, "Pasticcio");
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(FamilyNameReplacedEvent.class));
    FamilyNameReplacedEvent e = (FamilyNameReplacedEvent) event;
    assertThat(e.getFamilyName(), is("Pasticcio"));
    assertThat(e.getAccount().getUserInfo().getFamilyName(), is("Pasticcio"));
  }

  @Test
  void testSetNullFamilyName() {

    assertThat(ciccioAccount.getUserInfo().getFamilyName(), is("Paglia"));
    accountService.setAccountFamilyName(ciccioAccount, null);
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(FamilyNameReplacedEvent.class));
    FamilyNameReplacedEvent e = (FamilyNameReplacedEvent) event;
    assertThat(e.getFamilyName(), nullValue());
    assertThat(e.getAccount().getUserInfo().getFamilyName(), nullValue());

    accountService.setAccountFamilyName(ciccioAccount, null);
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetSameEmail() {

    assertThat(ciccioAccount.getUserInfo().getEmail(), is("ciccio@example.org"));
    accountService.setAccountEmail(ciccioAccount, "ciccio@example.org");
    verify(accountRepo, times(0)).save(ciccioAccount);
    verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetNewEmail() {

    assertThat(ciccioAccount.getUserInfo().getEmail(), is("ciccio@example.org"));
    accountService.setAccountEmail(ciccioAccount, "pasticcio@example.org");
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(EmailReplacedEvent.class));
    EmailReplacedEvent e = (EmailReplacedEvent) event;
    assertThat(e.getEmail(), is("pasticcio@example.org"));
    assertThat(e.getAccount().getUserInfo().getEmail(), is("pasticcio@example.org"));
  }

  @Test
  void testSetNullEmail() {

    assertThat(ciccioAccount.getUserInfo().getEmail(), is("ciccio@example.org"));
    assertThrows(NullPointerException.class,
        () -> accountService.setAccountEmail(ciccioAccount, null));
  }

  @Test
  void testSetAlreadyBoundEmail() {

    assertThat(ciccioAccount.getUserInfo().getEmail(), is("ciccio@example.org"));
    assertThrows(EmailAlreadyBoundException.class,
        () -> accountService.setAccountEmail(ciccioAccount, "test@example.org"));
  }

  @Test
  void testSetSameNullEndTime() {

    assertThat(ciccioAccount.getEndTime(), nullValue());
    accountService.setAccountEndTime(ciccioAccount, null);
    verify(accountRepo, times(0)).save(ciccioAccount);
    verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetSameNotNullEndTime() {

    Date updatedEndTime = Date.from(clock.instant());
    accountService.setAccountEndTime(ciccioAccount, updatedEndTime);
    assertThat(ciccioAccount.getEndTime(), is(updatedEndTime));
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    AccountEndTimeUpdatedEvent e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), nullValue());
    assertThat(e.getAccount().getEndTime(), is(updatedEndTime));

    accountService.setAccountEndTime(ciccioAccount, updatedEndTime);
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetEndTimeWorks() {

    Date updatedEndTime = Date.from(clock.instant());
    accountService.setAccountEndTime(ciccioAccount, updatedEndTime);
    verify(accountRepo, times(1)).save(ciccioAccount);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    AccountEndTimeUpdatedEvent e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), nullValue());
    assertThat(e.getAccount().getEndTime(), is(updatedEndTime));

    accountService.setAccountEndTime(ciccioAccount, null);
    verify(accountRepo, times(2)).save(ciccioAccount);
    verify(eventPublisher, times(2)).publishEvent(eventCaptor.capture());

    event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), is(updatedEndTime));
    assertThat(e.getAccount().getEndTime(), nullValue());
  }

  @Test
  void testNewAccountAddedToDefaultGroups() {

    IamGroup testGroup = new IamGroup();
    testGroup.setName(TEST_GROUP_1);
    DefaultGroup defaultGroup = new DefaultGroup();
    defaultGroup.setName(TEST_GROUP_1);
    defaultGroup.setEnrollment("INSERT");
    List<DefaultGroup> defaultGroups = Arrays.asList(defaultGroup);

    registrationProperties.setDefaultGroups(defaultGroups);
    lenient().when(iamGroupService.findByName(TEST_GROUP_1)).thenReturn(Optional.of(testGroup));

    ciccioAccount = accountService.createAccount(ciccioAccount);

    assertEquals(testGroup, getGroup(ciccioAccount));
  }

  private IamGroup getGroup(IamAccount account) {

    Optional<IamAccountGroupMembership> groupMembershipOptional =
        account.getGroups().stream().findFirst();
    if (groupMembershipOptional.isPresent()) {
      return groupMembershipOptional.get().getGroup();
    }
    return null;
  }

  @Test
  void testNoDefaultGroupsAddedWhenDefaultGroupsNotGiven() {

    ciccioAccount = accountService.createAccount(ciccioAccount);

    Optional<IamAccountGroupMembership> groupMembershipOptional =
        ciccioAccount.getGroups().stream().findFirst();
    assertFalse(groupMembershipOptional.isPresent());
  }

}
