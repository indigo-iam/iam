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
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Calendar;
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

  Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());

  DefaultIamAccountService accountService;

  @Captor
  ArgumentCaptor<ApplicationEvent> eventCaptor;

  @BeforeEach
  void setup() {

    lenient().when(accountRepo.findByCertificateSubject(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findBySshKeyValue(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findBySamlId(any())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByUsername(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByEmail(anyString())).thenReturn(Optional.empty());
    lenient().when(accountRepo.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TEST_ACCOUNT));
    lenient().when(accountRepo.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(TEST_ACCOUNT));
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

    lenient().when(authoritiesRepo.findByAuthority("ROLE_USER")).thenReturn(Optional.empty());

    IllegalStateException e = assertThrows(IllegalStateException.class,
        () -> accountService.createAccount(CICCIO_ACCOUNT));
    assertThat(e.getMessage(), equalTo("ROLE_USER not found in database. This is a bug"));
  }


  @Test
  void testUuidIfProvidedIsPreserved() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    accountService.createAccount(account);
    verify(accountRepo, Mockito.times(1)).save(account);
    assertThat(account.getUuid(), equalTo(CICCIO_UUID));

  }

  @Test
  void testUuidIfNotProvidedIsGenerated() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account.setUuid(null);

    accountService.createAccount(account);
    verify(accountRepo, Mockito.times(1)).save(account);
    assertNotNull(account.getUuid());
  }

  @Test
  void testCreationTimeIfProvidedIsPreserved() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DAY_OF_MONTH, -1);

    Date yesterday = cal.getTime();

    account.setCreationTime(yesterday);
    accountService.createAccount(account);
    verify(accountRepo, times(1)).save(account);
    assertThat(account.getCreationTime(), equalTo(yesterday));
  }

  @Test
  void testPasswordIfProvidedIsPreservedAndEncoded() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account.setPassword(PASSWORD);

    accountService.createAccount(account);
    verify(accountRepo, Mockito.times(1)).save(account);
    verify(passwordEncoder, Mockito.times(1)).encode(PASSWORD);

    assertThat(account.getPassword(), equalTo(PASSWORD));
  }

  @Test
  void testNullSamlIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getSamlIds().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null saml id"));
  }

  @Test
  void testNullSamlIdpIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    account.linkSamlIds(asList(samlId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty idpId"));
  }

  @Test
  void testEmptySamlIdpIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId("");
    account.linkSamlIds(asList(samlId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty idpId"));
  }

  @Test
  void testNullSamlUserIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);

    account.linkSamlIds(asList(samlId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty userId"));
  }

  @Test
  void testEmptySamlUserIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId("");

    account.linkSamlIds(asList(samlId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty userId"));
  }

  @Test
  void testNullSamlAttributeIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId(TEST_SAML_ID_USER_ID);

    account.linkSamlIds(asList(samlId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty attributeId"));
  }

  @Test
  void testEmptySamlAttributeIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId(TEST_SAML_ID_USER_ID);
    samlId.setAttributeId("");

    account.linkSamlIds(asList(samlId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty attributeId"));
  }


  @Test
  void testBoundSamlIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    lenient().when(accountRepo.findBySamlId(TEST_SAML_ID)).thenReturn(Optional.of(TEST_ACCOUNT));
    account.linkSamlIds(asList(TEST_SAML_ID));
    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(account));
  }

  @Test
  void testValidSamlIdLinkedPassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account.linkSamlIds(asList(TEST_SAML_ID));
    assertDoesNotThrow(() -> accountService.createAccount(account));
  }

  @Test
  void testNullOidcIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getOidcIds().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null oidc id"));
  }

  @Test
  void testNullOidcIdIssuerIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    account.linkOidcIds(asList(oidcId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty oidc id issuer"));
  }

  @Test
  void testEmptyOidcIdIssuerIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer("");
    account.linkOidcIds(asList(oidcId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty oidc id issuer"));
  }

  @Test
  void testNullOidcIdSubjectIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(TEST_OIDC_ID_ISSUER);
    account.linkOidcIds(asList(oidcId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty oidc id subject"));
  }

  @Test
  void testEmptyOidcIdSubjectIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(TEST_OIDC_ID_ISSUER);
    oidcId.setSubject("");
    account.linkOidcIds(asList(oidcId));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty oidc id subject"));
  }

  @Test
  void testBoundOidcIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    lenient().when(accountRepo.findByOidcId(TEST_OIDC_ID_ISSUER, TEST_OIDC_ID_SUBJECT))
      .thenReturn(Optional.of(TEST_ACCOUNT));

    account.linkOidcIds(asList(TEST_OIDC_ID));
    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(account));
  }


  @Test
  void testValidOidcIdPassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkOidcIds(asList(TEST_OIDC_ID));
    assertDoesNotThrow(() -> accountService.createAccount(account));
  }


  @Test
  void testNullSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getSshKeys().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null ssh key"));
  }

  @Test
  void testNoValueSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSshKey key = new IamSshKey();
    account.linkSshKeys(asList(key));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty ssh key value"));
  }

  @Test
  void testEmptyValueSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSshKey key = new IamSshKey();
    key.setValue("");
    account.linkSshKeys(asList(key));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty ssh key value"));
  }

  @Test
  void testBoundSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkSshKeys(asList(TEST_SSH_KEY_1));
    lenient().when(accountRepo.findBySshKeyValue(TEST_SSH_KEY_VALUE_1))
      .thenReturn(Optional.of(TEST_ACCOUNT));
    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(account));
  }

  @Test
  void testValidSshKeyPassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkSshKeys(asList(TEST_SSH_KEY_1));
    assertDoesNotThrow(() -> accountService.createAccount(account));
  }

  @Test
  void testNullX509CertificateIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getX509Certificates().add(null);
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null X.509 certificate"));
  }

  @Test
  void testNullX509CertificateSubjectIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    account.linkX509Certificates(asList(cert));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate subject DN"));
  }

  @Test
  void testNullX509CertificateIssuerIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    account.linkX509Certificates(asList(cert));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate issuer DN"));
  }

  @Test
  void testNullX509CertificateLabelIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    cert.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    account.linkX509Certificates(asList(cert));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate label"));
  }

  @Test
  void testEmptyX509CertificateLabelIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    cert.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    cert.setLabel("");
    account.linkX509Certificates(asList(cert));
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("null or empty X.509 certificate label"));
  }

  @Test
  void testBoundX509CertificateIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_1));

    lenient().when(accountRepo.findByCertificateSubject(TEST_X509_CERTIFICATE_SUBJECT_1))
      .thenReturn(Optional.of(TEST_ACCOUNT));

    assertThrows(CredentialAlreadyBoundException.class,
        () -> accountService.createAccount(account));
  }

  @Test
  void testValidX509CertificatePassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_2));
    assertDoesNotThrow(() -> accountService.createAccount(account));
  }

  @Test
  void testX509PrimaryIsBoundIfNotProvided() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_1, TEST_X509_CERTIFICATE_2));
    accountService.createAccount(account);

    for (IamX509Certificate cert : account.getX509Certificates()) {
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
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    TEST_X509_CERTIFICATE_2.setPrimary(true);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_1, TEST_X509_CERTIFICATE_2));
    accountService.createAccount(account);

    for (IamX509Certificate cert : account.getX509Certificates()) {
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
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    TEST_X509_CERTIFICATE_1.setPrimary(true);
    TEST_X509_CERTIFICATE_2.setPrimary(true);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_1, TEST_X509_CERTIFICATE_2));
    InvalidCredentialException e =
        assertThrows(InvalidCredentialException.class, () -> accountService.createAccount(account));
    assertThat(e.getMessage(), equalTo("Only one X.509 certificate can be marked as primary"));
  }

  @Test
  void testSshKeyPrimaryIsBoundIfNotProvided() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkSshKeys(asList(TEST_SSH_KEY_1, TEST_SSH_KEY_2));
    accountService.createAccount(account);

    for (IamSshKey key : account.getSshKeys()) {
      if (key.getValue().equals(TEST_SSH_KEY_1.getValue())) {
        assertTrue(key.isPrimary());
      }
      if (key.getValue().equals(TEST_SSH_KEY_2.getValue())) {
        assertFalse(key.isPrimary());
      }
    }
  }

  @Test
  void testSshKeyPrimaryIsRespected() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    TEST_SSH_KEY_2.setPrimary(true);
    account.linkSshKeys(asList(TEST_SSH_KEY_1, TEST_SSH_KEY_2));
    accountService.createAccount(account);

    for (IamSshKey key : account.getSshKeys()) {
      if (key.getValue().equals(TEST_SSH_KEY_1.getValue())) {
        assertFalse(key.isPrimary());
      }
      if (key.getValue().equals(TEST_SSH_KEY_2.getValue())) {
        assertTrue(key.isPrimary());
      }
    }

  }

  @Test
  void testMultiplePrimarySshKeysIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    TEST_SSH_KEY_1.setPrimary(true);
    TEST_SSH_KEY_2.setPrimary(true);
    account.linkSshKeys(asList(TEST_SSH_KEY_1, TEST_SSH_KEY_2));
    InvalidCredentialException e =
        assertThrows(InvalidCredentialException.class, () -> accountService.createAccount(account));
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
    accountService.deleteAccount(CICCIO_ACCOUNT);
    verify(accountRepo, times(1)).delete(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(any());
  }

  @Test
  void testMfaRemovedWhenAccountRemoved() {
    lenient().when(iamTotpMfaRepository.findByAccount(TOTP_MFA_ACCOUNT))
      .thenReturn(Optional.of(TOTP_MFA));

    accountService.deleteAccount(TOTP_MFA_ACCOUNT);

    verify(iamTotpMfaRepository, times(1)).delete(TOTP_MFA);
    verify(accountRepo, times(1)).delete(TOTP_MFA_ACCOUNT);
  }

  @Test
  void testSetEndTimeRequiresNonNullAccount() {
    NullPointerException e = assertThrows(NullPointerException.class,
        () -> accountService.setAccountEndTime(null, null));
    assertThat(e.getMessage(), containsString("Cannot set endTime on a null account"));
  }

  @Test
  void testSetSameGivenName() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getGivenName(), is("Ciccio"));
    accountService.setAccountGivenName(CICCIO_ACCOUNT, "Ciccio");
    verify(accountRepo, times(0)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetNewGivenName() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getGivenName(), is("Ciccio"));
    accountService.setAccountGivenName(CICCIO_ACCOUNT, "Pasticcio");
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(GivenNameReplacedEvent.class));
    GivenNameReplacedEvent e = (GivenNameReplacedEvent) event;
    assertThat(e.getGivenName(), is("Pasticcio"));
    assertThat(e.getAccount().getUserInfo().getGivenName(), is("Pasticcio"));
  }

  @Test
  void testSetNullGivenName() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getGivenName(), is("Ciccio"));
    accountService.setAccountGivenName(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(GivenNameReplacedEvent.class));
    GivenNameReplacedEvent e = (GivenNameReplacedEvent) event;
    assertThat(e.getGivenName(), nullValue());
    assertThat(e.getAccount().getUserInfo().getGivenName(), nullValue());

    accountService.setAccountGivenName(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetSameFamilyName() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getFamilyName(), is("Paglia"));
    accountService.setAccountFamilyName(CICCIO_ACCOUNT, "Paglia");
    verify(accountRepo, times(0)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetNewFamilyName() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getFamilyName(), is("Paglia"));
    accountService.setAccountFamilyName(CICCIO_ACCOUNT, "Pasticcio");
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(FamilyNameReplacedEvent.class));
    FamilyNameReplacedEvent e = (FamilyNameReplacedEvent) event;
    assertThat(e.getFamilyName(), is("Pasticcio"));
    assertThat(e.getAccount().getUserInfo().getFamilyName(), is("Pasticcio"));
  }

  @Test
  void testSetNullFamilyName() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getFamilyName(), is("Paglia"));
    accountService.setAccountFamilyName(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(FamilyNameReplacedEvent.class));
    FamilyNameReplacedEvent e = (FamilyNameReplacedEvent) event;
    assertThat(e.getFamilyName(), nullValue());
    assertThat(e.getAccount().getUserInfo().getFamilyName(), nullValue());

    accountService.setAccountFamilyName(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetSameEmail() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getEmail(), is("ciccio@example.org"));
    accountService.setAccountEmail(CICCIO_ACCOUNT, "ciccio@example.org");
    verify(accountRepo, times(0)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetNewEmail() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getEmail(), is("ciccio@example.org"));
    accountService.setAccountEmail(CICCIO_ACCOUNT, "pasticcio@example.org");
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(EmailReplacedEvent.class));
    EmailReplacedEvent e = (EmailReplacedEvent) event;
    assertThat(e.getEmail(), is("pasticcio@example.org"));
    assertThat(e.getAccount().getUserInfo().getEmail(), is("pasticcio@example.org"));
  }

  @Test
  void testSetNullEmail() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getEmail(), is("ciccio@example.org"));
    assertThrows(NullPointerException.class,
        () -> accountService.setAccountEmail(CICCIO_ACCOUNT, null));
  }

  @Test
  void testSetAlreadyBoundEmail() {

    assertThat(CICCIO_ACCOUNT.getUserInfo().getEmail(), is("ciccio@example.org"));
    assertThrows(EmailAlreadyBoundException.class,
        () -> accountService.setAccountEmail(CICCIO_ACCOUNT, "test@example.org"));
  }

  @Test
  void testSetSameNullEndTime() {

    assertThat(CICCIO_ACCOUNT.getEndTime(), nullValue());
    accountService.setAccountEndTime(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(0)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(0)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetSameNotNullEndTime() {

    Date updatedEndTime = new Date();
    accountService.setAccountEndTime(CICCIO_ACCOUNT, updatedEndTime);
    assertThat(CICCIO_ACCOUNT.getEndTime(), is(updatedEndTime));
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    AccountEndTimeUpdatedEvent e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), nullValue());
    assertThat(e.getAccount().getEndTime(), is(updatedEndTime));

    accountService.setAccountEndTime(CICCIO_ACCOUNT, updatedEndTime);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
  }

  @Test
  void testSetEndTimeWorks() {

    Date updatedEndTime = new Date();
    accountService.setAccountEndTime(CICCIO_ACCOUNT, updatedEndTime);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    AccountEndTimeUpdatedEvent e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), nullValue());
    assertThat(e.getAccount().getEndTime(), is(updatedEndTime));

    accountService.setAccountEndTime(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(2)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(2)).publishEvent(eventCaptor.capture());

    event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), is(updatedEndTime));
    assertThat(e.getAccount().getEndTime(), nullValue());
  }

  @Test
  void testNewAccountAddedToDefaultGroups() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    IamGroup testGroup = new IamGroup();
    testGroup.setName(TEST_GROUP_1);
    DefaultGroup defaultGroup = new DefaultGroup();
    defaultGroup.setName(TEST_GROUP_1);
    defaultGroup.setEnrollment("INSERT");
    List<DefaultGroup> defaultGroups = Arrays.asList(defaultGroup);

    registrationProperties.setDefaultGroups(defaultGroups);
    lenient().when(iamGroupService.findByName(TEST_GROUP_1)).thenReturn(Optional.of(testGroup));

    account = accountService.createAccount(account);

    assertTrue(getGroup(account).equals(testGroup));
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
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account = accountService.createAccount(account);

    Optional<IamAccountGroupMembership> groupMembershipOptional =
        account.getGroups().stream().findFirst();
    assertFalse(groupMembershipOptional.isPresent());
  }
}
