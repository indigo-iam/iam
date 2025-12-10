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
package it.infn.mw.iam.test.scim.updater;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Adders;
import it.infn.mw.iam.api.scim.updater.builders.Removers;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.api.scim.updater.util.CollectionHelpers;
import it.infn.mw.iam.audit.events.account.ServiceAccountReplacedEvent;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@ExtendWith(SpringExtension.class)
@IamNoMvcTest
public class AccountUpdatersTests extends X509TestSupport {

  public static final String OLD = "old";
  public static final String NEW = "new";

  public static final IamOidcId OLD_OIDC_ID = new IamOidcId(OLD, OLD);
  public static final IamOidcId NEW_OIDC_ID = new IamOidcId(NEW, NEW);

  public static final IamSamlId OLD_SAML_ID =
      new IamSamlId(OLD, Saml2Attribute.EPUID.getAttributeName(), OLD);

  public static final IamSamlId NEW_SAML_ID =
      new IamSamlId(NEW, Saml2Attribute.EPUID.getAttributeName(), NEW);

  public static final IamSshKey OLD_SSHKEY;
  public static final IamSshKey NEW_SSHKEY;

  static {
    NEW_SSHKEY = new IamSshKey(NEW);

    NEW_SSHKEY.setCreationTime(Date.from(Instant.now()));
    NEW_SSHKEY.setLastUpdateTime(Date.from(Instant.now()));
    NEW_SSHKEY.setLabel(NEW);
    NEW_SSHKEY.setFingerprint(NEW);

    OLD_SSHKEY = new IamSshKey(OLD);
    OLD_SSHKEY.setCreationTime(Date.from(Instant.now()));
    OLD_SSHKEY.setLastUpdateTime(Date.from(Instant.now()));
    OLD_SSHKEY.setLabel(OLD);
    OLD_SSHKEY.setFingerprint(OLD);
  }

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  private PasswordEncoder encoder;

  @Autowired
  private UsernameValidator usernameValidator;

  @Mock
  private ApplicationEventPublisher publisher;

  @Autowired
  private X509CertificateConverter x509Converter;

  private IamAccount account;
  private IamAccount other;

  private IamAccount newAccount(String username) {
    IamAccount account = new IamAccount();
    account.setUserInfo(new IamUserInfo());

    account.setUsername(username);
    account.setUuid(UUID.randomUUID().toString());
    account.setUserInfo(new IamUserInfo());
    account.getUserInfo().setEmail(String.format("%s@test.io", username));
    account.getUserInfo().setGivenName("test");
    account.getUserInfo().setFamilyName("user");
    return accountService.createAccount(account);
  }

  private Adders accountAdders() {
    return AccountUpdaters.adders(accountRepo, accountService, encoder, account,
        accessTokenRepository, refreshTokenRepository, usernameValidator);
  }

  private Removers accountRemovers() {
    return AccountUpdaters.removers(accountRepo, accountService, account);
  }

  private Replacers accountReplacers() {
    return AccountUpdaters.replacers(accountRepo, accountService, encoder, account,
        accessTokenRepository, refreshTokenRepository, usernameValidator);
  }

  @BeforeEach
  void before() {
    account = newAccount("account");
    other = newAccount("other");
  }

  @Test
  void testCollectionHelperNotNullOrEmpty() {

    assertThat(CollectionHelpers.notNullOrEmpty(Lists.newArrayList()), equalTo(false));
    assertThat(CollectionHelpers.notNullOrEmpty(null), equalTo(false));
  }

  @Test
  void testPasswordAdderWorks() {

    account.setPassword(encoder.encode(OLD));
    accountRepo.save(account);

    Updater u = accountAdders().password(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testGivenNameAdderWorks() {

    account.setUserInfo(new IamUserInfo());
    account.getUserInfo().setGivenName(OLD);

    Updater u = accountAdders().givenName(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testFamilyNameAdderWorks() {

    account.getUserInfo().setFamilyName(OLD);

    Updater u = accountAdders().familyName(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testEmailAdderFailsWhenEmailIsBoundToAnotherUser() {

    account.getUserInfo().setEmail(OLD);

    other.getUserInfo().setEmail(NEW);
    accountRepo.save(other);

    assertThrows(ScimResourceExistsException.class, () -> accountAdders().email(NEW).update());
  }

  @Test
  void testEmailAdderWorks() {

    account.getUserInfo().setEmail(OLD);

    accountRepo.save(account);

    Updater u = accountAdders().email(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testPictureAdderWorks() {
    account.getUserInfo().setPicture(OLD);

    Updater u = accountAdders().picture(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testPictureAdderWorksForNullValue() {
    account.getUserInfo().setPicture(OLD);
    accountRepo.save(account);

    Updater u = accountAdders().picture(null);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testOidcIdAdderWorks() {

    Updater u = accountAdders().oidcId(Lists.newArrayList(NEW_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));
  }

  @Test
  void testOidcIdAdderWorksWithNoUpdate() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(Lists.newArrayList(NEW_OIDC_ID));

    assertThat(u.update(), is(false));
  }

  @Test
  void testOidcIdAdderFailsWhenOidcIdIsLinkedToAnotherAccount() {

    other.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(other);

    assertThat(accountRepo.findByOidcId(NEW, NEW)
      .orElseThrow(() -> new AssertionError("Expected account not found!")), is(other));

    assertThrows(ScimResourceExistsException.class,
        () -> accountAdders().oidcId(newArrayList(NEW_OIDC_ID)).update());
  }

  @Test
  void testOidcIdAdderWorksWithUpdate() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));

    account.linkOidcIds(singletonList(OLD_OIDC_ID));

    accountRepo.save(account);

    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));
  }

  @Test
  void testOidcIdAdderWorksWithListContainingNull() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(newArrayList(NEW_OIDC_ID, null));

    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));
  }

  @Test
  void testOidcIdAdderWorksWithListContainingDuplicates() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(newArrayList(NEW_OIDC_ID, NEW_OIDC_ID, OLD_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));
  }

  @Test
  void testOidcIdRemoverWorks() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(NEW_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  void testOidcIdRemoverWorksWithNoUpdate() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(OLD_OIDC_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));
  }

  @Test
  void testOidcIdRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().oidcId(newArrayList(OLD_OIDC_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  void testOidcIdRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().oidcId(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  void testOidcIdRemoverWorksWithMultipleValues() {

    account.linkOidcIds(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  void testOidcIdRemoverWorksWithNullAndDuplicatesValues() {

    account.linkOidcIds(newArrayList(NEW_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID, null, OLD_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  void testSamlIdAdderWorks() {

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));
  }

  @Test
  void testSamlIdAdderWorksWithNoUpdate() {

    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));
  }


  @Test
  void testSamlIdAdderFailsWhenSamlIdLinkedToAnotherAccount() {
    other.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(other);

    assertThrows(ScimResourceExistsException.class,
        () -> accountAdders().samlId(newArrayList(NEW_SAML_ID)).update());
  }

  @Test
  void testSamlIdAdderFailsWhenSamlIdLinkedToTheSameAccount() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }

  @Test
  void testSamlAdderWorksWithListContainingNull() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID, null, null));
    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }


  @Test
  void testSamlAdderWorksWithListContainingDuplicates() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);


    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID, NEW_SAML_ID, OLD_SAML_ID));
    assertThat(u.update(), is(true));

    assertThat(account.getSamlIds(), hasSize(2));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID, OLD_SAML_ID));

  }

  @Test
  void testSamlRemoverWorks() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(NEW_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));
  }


  @Test
  void testSamlRemoverWorksWithNoUpdate() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(OLD_SAML_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));
  }


  @Test
  void testSamlRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().samlId(newArrayList(OLD_SAML_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(0));

  }


  @Test
  void testSamlRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().samlId(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  void testSamlRemoverWorksWithMultipleValues() {

    account.linkSamlIds(newArrayList(NEW_SAML_ID, OLD_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(NEW_SAML_ID, OLD_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  void testSamlRemoverWorksWithNullAndDuplicatesValues() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(NEW_SAML_ID, OLD_SAML_ID, null, OLD_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));

  }


  @Test
  void testSshKeyAdderWorks() {

    Updater u = accountAdders().sshKey(Lists.newArrayList(NEW_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));

  }

  @Test
  void testSshKeyAdderWorksWithNoUpdate() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY));

    assertThat(u.update(), is(false));

  }

  @Test
  void testSshKeyAdderFailsWhenSshKeyIsLinkedToAnotherAccount() {
    other.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(other);

    assertThrows(ScimResourceExistsException.class,
        () -> accountAdders().sshKey(Lists.newArrayList(NEW_SSHKEY)).update());
  }

  @Test
  void testSshKeyAdderWorksWithUpdate() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));

    account.linkSshKeys(singletonList(OLD_SSHKEY));
    accountRepo.save(account);

    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));
  }

  @Test
  void testSshKeyAdderWorksWithListContainingNull() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY, null));

    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));
  }

  @Test
  void testSshKeyAdderWorksWithListContainingDuplicates() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY, NEW_SSHKEY, OLD_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));
  }

  @Test
  void testSshKeyRemoverWorks() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(NEW_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  void testSshKeyRemoverWorksWithNoUpdate() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(OLD_SSHKEY));
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));
  }


  @Test
  void testSshKeyRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().sshKey(newArrayList(OLD_SSHKEY));
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  void testSshKeyRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().sshKey(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  void testSshKeyRemoverWorksWithMultipleValues() {

    account.linkSshKeys(newArrayList(NEW_SSHKEY, OLD_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  void testSshKeyRemoverWorksWithNullAndDuplicatesValues() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY, null, OLD_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  void testX509CertificateAdderWorks() {

    Updater u = accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT));
  }

  @Test
  void testX509CertificateParsingWorks() {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .display("test")
      .build();

    assertDoesNotThrow(() -> x509Converter.entityFromDto(cert));
  }

  @Test
  void testX509CertificateAdderWorksWithNoUpdate() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u = accountAdders().x509Certificate(Lists.newArrayList(TEST_0_IAM_X509_CERT));

    assertThat(u.update(), is(false));
  }

  @Test
  void testX509CertificateAdderFailsWhenX509CertificateIsLinkedToAnotherAccount() {

    other.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(other);
    assertThrows(ScimResourceExistsException.class,
        () -> accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT)).update());
  }

  @Test
  void testX509CertificateAdderWorksWithUpdate() {
    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u =
        accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));

    account.linkX509Certificates(singletonList(TEST_1_IAM_X509_CERT));
    accountRepo.save(account);

    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
  }

  @Test
  void testX509CertificateAdderWorksWithListContainingNull() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);


    Updater u = accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT, null));

    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT));
  }

  @Test
  void testX509CertificateAdderWorksWithListContainingDuplicates() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);


    Updater u = accountAdders().x509Certificate(
        newArrayList(TEST_0_IAM_X509_CERT, TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
  }

  @Test
  void testX509CertificateRemoverWorks() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u = accountRemovers().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  void testX509CertificateRemoverWorksWithNoUpdate() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u = accountRemovers().x509Certificate(newArrayList(TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT));
  }

  @Test
  void testX509CertificateRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().x509Certificate(newArrayList(TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  void testX509CertificateRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().x509Certificate(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  void testX509CertificateRemoverWorksWithMultipleValues() {

    account.linkX509Certificates(newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u =
        accountRemovers().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  void testX509CertificateRemoverWorksWithNullAndDuplicatesValues() {
    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);


    Updater u = accountRemovers().x509Certificate(
        newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT, null, TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  void testUsernameReplacerWorks() {

    account.setUsername(OLD);
    accountRepo.save(account);

    Updater u = accountReplacers().username(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testActiveReplacerWorks() {

    account.setActive(false);
    accountRepo.save(account);

    Updater u = accountReplacers().active(true);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testPictureRemoverWorks() {
    account.getUserInfo().setPicture(OLD);
    accountRepo.save(account);

    Updater u = accountRemovers().picture(OLD);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testServiceAccountReplacerWorks() {

    account.setServiceAccount(false);
    accountRepo.save(account);

    Updater u = accountReplacers().serviceAccount(true);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  void testPublishEventIsCalledWithServiceAccountReplacedEvent() {

    account.setServiceAccount(false);
    accountRepo.save(account);

    Updater u = accountReplacers().serviceAccount(true);
    assertThat(u.update(), is(true));

    u.publishUpdateEvent(this, publisher);
    verify(publisher, times(1)).publishEvent(any(ServiceAccountReplacedEvent.class));
  }
}
