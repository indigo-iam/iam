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
import static java.util.Collections.emptyList;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

import com.google.common.collect.Sets;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.audit.events.account.AccountEndTimeUpdatedEvent;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.core.user.DefaultIamAccountService;
import it.infn.mw.iam.core.user.exception.CredentialAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.InvalidCredentialException;
import it.infn.mw.iam.core.user.exception.UserAlreadyExistsException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;

@RunWith(MockitoJUnitRunner.class)
public class IamAccountServiceTests extends IamAccountServiceTestSupport {

  public static final Instant NOW = Instant.parse("2021-01-01T00:00:00.00Z");

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private IamGroupRepository groupRepo;

  @Mock
  private IamAuthoritiesRepository authoritiesRepo;

  @Mock
  private IamAccountClientRepository accountClientRepo;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private ApplicationEventPublisher eventPublisher;

  @Mock
  private TimeProvider timeProvider;

  @Mock
  private OAuth2TokenEntityService tokenService;

  private Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());

  private DefaultIamAccountService accountService;

  @Captor
  private ArgumentCaptor<ApplicationEvent> eventCaptor;

  @Before
  public void setup() {

    when(accountRepo.findProvisionedAccountsWithLastLoginTimeBeforeTimestamp(any()))
      .thenReturn(emptyList());
    when(accountRepo.findByCertificateSubject(anyString())).thenReturn(Optional.empty());
    when(accountRepo.findBySshKeyValue(anyString())).thenReturn(Optional.empty());
    when(accountRepo.findBySamlId(any())).thenReturn(Optional.empty());
    when(accountRepo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());
    when(accountRepo.findByUsername(anyString())).thenReturn(Optional.empty());
    when(accountRepo.findByEmail(anyString())).thenReturn(Optional.empty());
    when(accountRepo.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TEST_ACCOUNT));
    when(accountRepo.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(TEST_ACCOUNT));
    when(accountRepo.save(any(IamAccount.class))).thenAnswer(i -> i.getArguments()[0]);
    when(authoritiesRepo.findByAuthority(anyString())).thenReturn(Optional.empty());
    when(authoritiesRepo.findByAuthority("ROLE_USER")).thenReturn(Optional.of(ROLE_USER_AUTHORITY));
    when(passwordEncoder.encode(any())).thenReturn(PASSWORD);

    accountService = new DefaultIamAccountService(clock, accountRepo, groupRepo, authoritiesRepo,
        passwordEncoder, eventPublisher, tokenService, accountClientRepo);
  }

  @Test(expected = NullPointerException.class)
  public void testCreateNullAccountFails() {
    try {
      accountService.createAccount(null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("Cannot create a null account"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullUsernameFails() {
    IamAccount account = IamAccount.newAccount();
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("Null or empty username"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyUsernameFails() {
    IamAccount account = IamAccount.newAccount();
    account.setUsername("");
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("Null or empty username"));
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void testNullUserinfoFails() {
    IamAccount account = new IamAccount();
    account.setUsername("test");
    try {
      accountService.createAccount(account);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("Null userinfo object"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullEmailFails() {
    IamAccount account = IamAccount.newAccount();
    account.setUsername("test");

    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("Null or empty email"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyEmailFails() {
    IamAccount account = IamAccount.newAccount();
    account.setUsername("test");
    account.getUserInfo().setEmail("");

    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("Null or empty email"));
      throw e;
    }
  }


  @Test(expected = UserAlreadyExistsException.class)
  public void testBoundUsernameChecksWorks() {
    IamAccount account = IamAccount.newAccount();
    account.setUsername(TEST_USERNAME);
    account.getUserInfo().setEmail("cicciopaglia@test.org");

    try {
      accountService.createAccount(account);
    } catch (UserAlreadyExistsException e) {
      assertThat(e.getMessage(),
          equalTo(String.format("A user with username '%s' already exists", TEST_USERNAME)));
      throw e;
    }

  }

  @Test(expected = UserAlreadyExistsException.class)
  public void testBoundEmailCheckWorks() {
    IamAccount account = IamAccount.newAccount();
    account.setUsername("ciccio");
    account.getUserInfo().setEmail(TEST_EMAIL);

    try {
      accountService.createAccount(account);
    } catch (UserAlreadyExistsException e) {
      assertThat(e.getMessage(),
          equalTo(String.format("A user linked with email '%s' already exists", TEST_EMAIL)));
      throw e;
    }
  }

  @Test(expected = IllegalStateException.class)
  public void testCreationFailsIfRoleUserAuthorityIsNotDefined() {

    when(authoritiesRepo.findByAuthority("ROLE_USER")).thenReturn(Optional.empty());

    try {
      accountService.createAccount(CICCIO_ACCOUNT);
    } catch (IllegalStateException e) {
      assertThat(e.getMessage(), equalTo("ROLE_USER not found in database. This is a bug"));
      throw e;
    }
  }


  @Test
  public void testUuidIfProvidedIsPreserved() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    accountService.createAccount(account);
    verify(accountRepo, Mockito.times(1)).save(account);
    assertThat(account.getUuid(), equalTo(CICCIO_UUID));

  }

  @Test
  public void testUuidIfNotProvidedIsGenerated() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account.setUuid(null);

    accountService.createAccount(account);
    verify(accountRepo, Mockito.times(1)).save(account);
    assertNotNull(account.getUuid());
  }

  @Test
  public void testCreationTimeIfProvidedIsPreserved() {
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
  public void testPasswordIfProvidedIsPreservedAndEncoded() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account.setPassword(PASSWORD);

    accountService.createAccount(account);
    verify(accountRepo, Mockito.times(1)).save(account);
    verify(passwordEncoder, Mockito.times(1)).encode(PASSWORD);

    assertThat(account.getPassword(), equalTo(PASSWORD));
  }

  @Test(expected = NullPointerException.class)
  public void testNullSamlIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getSamlIds().add(null);
    try {
      accountService.createAccount(account);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("null saml id"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullSamlIdpIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    account.linkSamlIds(asList(samlId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty idpId"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptySamlIdpIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId("");
    account.linkSamlIds(asList(samlId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty idpId"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullSamlUserIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);

    account.linkSamlIds(asList(samlId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty userId"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptySamlUserIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId("");

    account.linkSamlIds(asList(samlId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty userId"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullSamlAttributeIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId(TEST_SAML_ID_USER_ID);

    account.linkSamlIds(asList(samlId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty attributeId"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptySamlAttributeIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(TEST_SAML_ID_IDP_ID);
    samlId.setUserId(TEST_SAML_ID_USER_ID);
    samlId.setAttributeId("");

    account.linkSamlIds(asList(samlId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty attributeId"));
      throw e;
    }
  }


  @Test(expected = CredentialAlreadyBoundException.class)
  public void testBoundSamlIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    when(accountRepo.findBySamlId(TEST_SAML_ID)).thenReturn(Optional.of(TEST_ACCOUNT));
    account.linkSamlIds(asList(TEST_SAML_ID));
    accountService.createAccount(account);
  }

  @Test
  public void testValidSamlIdLinkedPassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);

    account.linkSamlIds(asList(TEST_SAML_ID));
    accountService.createAccount(account);

  }

  @Test(expected = NullPointerException.class)
  public void testNullOidcIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getOidcIds().add(null);
    try {
      accountService.createAccount(account);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("null oidc id"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullOidcIdIssuerIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    account.linkOidcIds(asList(oidcId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty oidc id issuer"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyOidcIdIssuerIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer("");
    account.linkOidcIds(asList(oidcId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty oidc id issuer"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullOidcIdSubjectIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(TEST_OIDC_ID_ISSUER);
    account.linkOidcIds(asList(oidcId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty oidc id subject"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyOidcIdSubjectIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(TEST_OIDC_ID_ISSUER);
    oidcId.setSubject("");
    account.linkOidcIds(asList(oidcId));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty oidc id subject"));
      throw e;
    }
  }

  @Test(expected = CredentialAlreadyBoundException.class)
  public void testBoundOidcIdIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    when(accountRepo.findByOidcId(TEST_OIDC_ID_ISSUER, TEST_OIDC_ID_SUBJECT))
      .thenReturn(Optional.of(TEST_ACCOUNT));

    account.linkOidcIds(asList(TEST_OIDC_ID));
    accountService.createAccount(account);
  }


  @Test
  public void testValidOidcIdPassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkOidcIds(asList(TEST_OIDC_ID));
    accountService.createAccount(account);

  }


  @Test(expected = NullPointerException.class)
  public void testNullSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getSshKeys().add(null);
    try {
      accountService.createAccount(account);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("null ssh key"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNoValueSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSshKey key = new IamSshKey();
    account.linkSshKeys(asList(key));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty ssh key value"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyValueSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamSshKey key = new IamSshKey();
    key.setValue("");
    account.linkSshKeys(asList(key));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty ssh key value"));
      throw e;
    }
  }

  @Test(expected = CredentialAlreadyBoundException.class)
  public void testBoundSshKeyIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkSshKeys(asList(TEST_SSH_KEY_1));
    when(accountRepo.findBySshKeyValue(TEST_SSH_KEY_VALUE_1)).thenReturn(Optional.of(TEST_ACCOUNT));
    accountService.createAccount(account);
  }

  @Test
  public void testValidSshKeyPassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkSshKeys(asList(TEST_SSH_KEY_1));
    accountService.createAccount(account);
  }

  @Test(expected = NullPointerException.class)
  public void testNullX509CertificateIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.getX509Certificates().add(null);
    try {
      accountService.createAccount(account);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("null X.509 certificate"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullX509CertificateSubjectIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    account.linkX509Certificates(asList(cert));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty X.509 certificate subject DN"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullX509CertificateIssuerIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    account.linkX509Certificates(asList(cert));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty X.509 certificate issuer DN"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullX509CertificateLabelIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    cert.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    account.linkX509Certificates(asList(cert));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty X.509 certificate label"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyX509CertificateLabelIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_X509_CERTIFICATE_SUBJECT_1);
    cert.setIssuerDn(TEST_X509_CERTIFICATE_ISSUER_1);
    cert.setLabel("");
    account.linkX509Certificates(asList(cert));
    try {
      accountService.createAccount(account);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), equalTo("null or empty X.509 certificate label"));
      throw e;
    }
  }

  @Test(expected = CredentialAlreadyBoundException.class)
  public void testBoundX509CertificateIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_1));

    when(accountRepo.findByCertificateSubject(TEST_X509_CERTIFICATE_SUBJECT_1))
      .thenReturn(Optional.of(TEST_ACCOUNT));

    accountService.createAccount(account);
  }

  @Test
  public void testValidX509CertificatePassesSanityChecks() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_2));
    accountService.createAccount(account);
  }

  @Test
  public void testX509PrimaryIsBoundIfNotProvided() {
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
  public void testX509PrimaryIsRespected() {
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

  @Test(expected = InvalidCredentialException.class)
  public void testX509MultiplePrimaryIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    TEST_X509_CERTIFICATE_1.setPrimary(true);
    TEST_X509_CERTIFICATE_2.setPrimary(true);
    account.linkX509Certificates(asList(TEST_X509_CERTIFICATE_1, TEST_X509_CERTIFICATE_2));
    try {
      accountService.createAccount(account);
    } catch (InvalidCredentialException e) {
      assertThat(e.getMessage(), equalTo("Only one X.509 certificate can be marked as primary"));
      throw e;
    }
  }

  @Test
  public void testSshKeyPrimaryIsBoundIfNotProvided() {
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
  public void testSshKeyPrimaryIsRespected() {
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

  @Test(expected = InvalidCredentialException.class)
  public void testMultiplePrimarySshKeysIsNotAccepted() {
    IamAccount account = cloneAccount(CICCIO_ACCOUNT);
    TEST_SSH_KEY_1.setPrimary(true);
    TEST_SSH_KEY_2.setPrimary(true);
    account.linkSshKeys(asList(TEST_SSH_KEY_1, TEST_SSH_KEY_2));
    try {
      accountService.createAccount(account);
    } catch (InvalidCredentialException e) {
      assertThat(e.getMessage(), equalTo("Only one SSH key can be marked as primary"));
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void testNullDeleteAccountFails() {
    try {
      accountService.deleteAccount(null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("cannot delete a null account"));
      throw e;
    }
  }

  @Test
  public void testAccountDeletion() {
    accountService.deleteAccount(CICCIO_ACCOUNT);
    verify(accountRepo, times(1)).delete(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(any());
  }

  @Test(expected = NullPointerException.class)
  public void testDeleteInactiveProvisionedAccountFailsWithNullTimestamp() {
    try {
      accountService.deleteInactiveProvisionedUsersSinceTime(null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("null timestamp"));
      throw e;
    }
  }

  @Test
  public void testDeleteInactiveProvisionedAccountWorks() {

    when(accountRepo.findProvisionedAccountsWithLastLoginTimeBeforeTimestamp(any()))
      .thenReturn(Arrays.asList(CICCIO_ACCOUNT, TEST_ACCOUNT));

    accountService.deleteInactiveProvisionedUsersSinceTime(new Date());

    verify(accountRepo, times(1)).delete(CICCIO_ACCOUNT);
    verify(accountRepo, times(1)).delete(TEST_ACCOUNT);
    verify(eventPublisher, times(2)).publishEvent(any());
  }

  @Test
  public void testTokensAreRemovedWhenAccountIsRemoved() {
    OAuth2AccessTokenEntity accessToken = mock(OAuth2AccessTokenEntity.class);
    OAuth2RefreshTokenEntity refreshToken = mock(OAuth2RefreshTokenEntity.class);

    when(tokenService.getAllAccessTokensForUser(CICCIO_USERNAME))
      .thenReturn(Sets.newHashSet(accessToken));
    when(tokenService.getAllRefreshTokensForUser(CICCIO_USERNAME))
      .thenReturn(Sets.newHashSet(refreshToken));


    accountService.deleteAccount(CICCIO_ACCOUNT);
    verify(tokenService).revokeAccessToken(Mockito.eq(accessToken));
    verify(tokenService).revokeRefreshToken(Mockito.eq(refreshToken));
  }

  @Test(expected = NullPointerException.class)
  public void testSetEndTimeRequiresNonNullAccount() {
    try {
      accountService.setAccountEndTime(null, null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), containsString("Cannot set endTime on a null account"));
      throw e;
    }
  }

  @Test
  public void testSetEndTimeWorksForNullDate() {
    accountService.setAccountEndTime(CICCIO_ACCOUNT, null);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    AccountEndTimeUpdatedEvent e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), nullValue());
    assertThat(e.getAccount().getEndTime(), nullValue());
  }

  @Test
  public void testSetEndTimeWorksForNonNullDate() {

    Date newEndTime = new Date();
    accountService.setAccountEndTime(CICCIO_ACCOUNT, newEndTime);
    verify(accountRepo, times(1)).save(CICCIO_ACCOUNT);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AccountEndTimeUpdatedEvent.class));

    AccountEndTimeUpdatedEvent e = (AccountEndTimeUpdatedEvent) event;
    assertThat(e.getPreviousEndTime(), nullValue());
    assertThat(e.getAccount().getEndTime(), is(newEndTime));
  }
}
