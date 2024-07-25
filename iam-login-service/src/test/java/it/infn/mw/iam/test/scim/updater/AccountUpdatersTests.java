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

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Adders;
import it.infn.mw.iam.api.scim.updater.builders.Removers;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.api.scim.updater.util.CollectionHelpers;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;


@RunWith(SpringRunner.class)
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
  private OAuth2TokenEntityService tokenService;

  @Autowired
  private PasswordEncoder encoder;

  @Autowired
  private UsernameValidator usernameValidator;

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
    return AccountUpdaters.adders(accountRepo, accountService, encoder, account, tokenService,
        usernameValidator);
  }

  private Removers accountRemovers() {
    return AccountUpdaters.removers(accountRepo, accountService, account);
  }

  private Replacers accountReplacers() {
    return AccountUpdaters.replacers(accountRepo, accountService, encoder, account, tokenService,
        usernameValidator);
  }

  @Before
  public void before() {
    account = newAccount("account");
    other = newAccount("other");
  }

  @Test
  public void testCollectionHelperNotNullOrEmpty() {

    assertThat(CollectionHelpers.notNullOrEmpty(Lists.newArrayList()), equalTo(false));
    assertThat(CollectionHelpers.notNullOrEmpty(null), equalTo(false));
  }

  @Test
  public void testPasswordAdderWorks() {

    account.setPassword(encoder.encode(OLD));
    accountRepo.save(account);

    Updater u = accountAdders().password(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }

  @Test
  public void testGivenNameAdderWorks() {

    account.setUserInfo(new IamUserInfo());
    account.getUserInfo().setGivenName(OLD);

    Updater u = accountAdders().givenName(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testFamilyNameAdderWorks() {

    account.getUserInfo().setFamilyName(OLD);

    Updater u = accountAdders().familyName(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test(expected = ScimResourceExistsException.class)
  public void testEmailAdderFailsWhenEmailIsBoundToAnotherUser() {

    account.getUserInfo().setEmail(OLD);

    other.getUserInfo().setEmail(NEW);
    accountRepo.save(other);

    accountAdders().email(NEW).update();
  }

  @Test
  public void testEmailAdderWorks() {

    account.getUserInfo().setEmail(OLD);

    accountRepo.save(account);

    Updater u = accountAdders().email(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }

  @Test
  public void testPictureAdderWorks() {
    account.getUserInfo().setPicture(OLD);

    Updater u = accountAdders().picture(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testPictureAdderWorksForNullValue() {
    account.getUserInfo().setPicture(OLD);
    accountRepo.save(account);

    Updater u = accountAdders().picture(null);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testOidcIdAdderWorks() {

    Updater u = accountAdders().oidcId(Lists.newArrayList(NEW_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));

  }

  @Test
  public void testOidcIdAdderWorksWithNoUpdate() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(Lists.newArrayList(NEW_OIDC_ID));

    assertThat(u.update(), is(false));

  }


  @Test(expected = ScimResourceExistsException.class)
  public void testOidcIdAdderFailsWhenOidcIdIsLinkedToAnotherAccount() {

    other.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(other);

    assertThat(accountRepo.findByOidcId(NEW, NEW)
      .orElseThrow(() -> new AssertionError("Expected account not found!")), is(other));

    accountAdders().oidcId(newArrayList(NEW_OIDC_ID)).update();

  }


  @Test
  public void testOidcIdAdderWorksWithUpdate() {

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
  public void testOidcIdAdderWorksWithListContainingNull() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(newArrayList(NEW_OIDC_ID, null));

    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));

  }

  @Test
  public void testOidcIdAdderWorksWithListContainingDuplicates() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));

    accountRepo.save(account);

    Updater u = accountAdders().oidcId(newArrayList(NEW_OIDC_ID, NEW_OIDC_ID, OLD_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));

  }

  @Test
  public void testOidcIdRemoverWorks() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(NEW_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  public void testOidcIdRemoverWorksWithNoUpdate() {

    account.linkOidcIds(singletonList(NEW_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(OLD_OIDC_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));
  }

  @Test
  public void testOidcIdRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().oidcId(newArrayList(OLD_OIDC_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(0));

  }

  @Test
  public void testOidcIdRemoverNoUpdateWithEmptyList2() {
    Updater u = accountRemovers().oidcId(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(0));

  }

  @Test
  public void testOidcIdRemoverWorksWithMultipleValues() {

    account.linkOidcIds(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));

  }

  @Test
  public void testOidcIdRemoverWorksWithNullAndDuplicatesValues() {

    account.linkOidcIds(newArrayList(NEW_OIDC_ID));
    accountRepo.save(account);


    Updater u = accountRemovers().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID, null, OLD_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  public void testSamlIdAdderWorks() {

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));
  }



  @Test
  public void testSamlIdAdderWorksWithNoUpdate() {

    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }


  @Test(expected = ScimResourceExistsException.class)
  public void testSamlIdAdderFailsWhenSamlIdLinkedToAnotherAccount() {
    other.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(other);

    accountAdders().samlId(newArrayList(NEW_SAML_ID)).update();

  }

  @Test
  public void testSamlIdAdderFailsWhenSamlIdLinkedToTheSameAccount() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }

  @Test
  public void testSamlAdderWorksWithListContainingNull() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID, null, null));
    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }


  @Test
  public void testSamlAdderWorksWithListContainingDuplicates() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);


    Updater u = accountAdders().samlId(newArrayList(NEW_SAML_ID, NEW_SAML_ID, OLD_SAML_ID));
    assertThat(u.update(), is(true));

    assertThat(account.getSamlIds(), hasSize(2));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID, OLD_SAML_ID));

  }

  @Test
  public void testSamlRemoverWorks() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(NEW_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));
  }


  @Test
  public void testSamlRemoverWorksWithNoUpdate() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(OLD_SAML_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));
  }


  @Test
  public void testSamlRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().samlId(newArrayList(OLD_SAML_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(0));

  }



  @Test
  public void testSamlRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().samlId(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  public void testSamlRemoverWorksWithMultipleValues() {

    account.linkSamlIds(newArrayList(NEW_SAML_ID, OLD_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(NEW_SAML_ID, OLD_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  public void testSamlRemoverWorksWithNullAndDuplicatesValues() {
    account.linkSamlIds(singletonList(NEW_SAML_ID));
    accountRepo.save(account);

    Updater u = accountRemovers().samlId(newArrayList(NEW_SAML_ID, OLD_SAML_ID, null, OLD_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));

  }


  @Test
  public void testSshKeyAdderWorks() {

    Updater u = accountAdders().sshKey(Lists.newArrayList(NEW_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));

  }

  @Test
  public void testSshKeyAdderWorksWithNoUpdate() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY));

    assertThat(u.update(), is(false));

  }



  @Test(expected = ScimResourceExistsException.class)
  public void testSshKeyAdderFailsWhenSshKeyIsLinkedToAnotherAccount() {
    other.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(other);

    accountAdders().sshKey(Lists.newArrayList(NEW_SSHKEY)).update();
  }


  @Test
  public void testSshKeyAdderWorksWithUpdate() {

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
  public void testSshKeyAdderWorksWithListContainingNull() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY, null));

    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));

  }

  @Test
  public void testSshKeyAdderWorksWithListContainingDuplicates() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountAdders().sshKey(newArrayList(NEW_SSHKEY, NEW_SSHKEY, OLD_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));

  }

  @Test
  public void testSshKeyRemoverWorks() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(NEW_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  public void testSshKeyRemoverWorksWithNoUpdate() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(OLD_SSHKEY));
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));
  }


  @Test
  public void testSshKeyRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().sshKey(newArrayList(OLD_SSHKEY));
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testSshKeyRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().sshKey(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testSshKeyRemoverWorksWithMultipleValues() {

    account.linkSshKeys(newArrayList(NEW_SSHKEY, OLD_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));

  }



  @Test
  public void testSshKeyRemoverWorksWithNullAndDuplicatesValues() {

    account.linkSshKeys(singletonList(NEW_SSHKEY));
    accountRepo.save(account);

    Updater u = accountRemovers().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY, null, OLD_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testX509CertificateAdderWorks() {

    Updater u = accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT));

  }


  @Test
  public void testX509CertificateAdderWorksWithNoUpdate() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u = accountAdders().x509Certificate(Lists.newArrayList(TEST_0_IAM_X509_CERT));

    assertThat(u.update(), is(false));

  }

  @Test(expected = ScimResourceExistsException.class)
  public void testX509CertificateAdderFailsWhenX509CertificateIsLinkedToAnotherAccount() {

    other.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(other);
    accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT)).update();

  }

  @Test
  public void testX509CertificateAdderWorksWithUpdate() {
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
  public void testX509CertificateAdderWorksWithListContainingNull() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);


    Updater u = accountAdders().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT, null));

    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT));

  }

  @Test
  public void testX509CertificateAdderWorksWithListContainingDuplicates() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);


    Updater u = accountAdders().x509Certificate(
        newArrayList(TEST_0_IAM_X509_CERT, TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));

  }

  @Test
  public void testX509CertificateRemoverWorks() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u = accountRemovers().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  public void testX509CertificateRemoverWorksWithNoUpdate() {

    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u = accountRemovers().x509Certificate(newArrayList(TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(TEST_0_IAM_X509_CERT));
  }

  @Test
  public void testX509CertificateRemoverNoUpdateWithEmptyList() {

    Updater u = accountRemovers().x509Certificate(newArrayList(TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testX509CertificateRemoverNoUpdateWithEmptyList2() {

    Updater u = accountRemovers().x509Certificate(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testX509CertificateRemoverWorksWithMultipleValues() {

    account.linkX509Certificates(newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
    accountRepo.save(account);

    Updater u =
        accountRemovers().x509Certificate(newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testX509CertificateRemoverWorksWithNullAndDuplicatesValues() {
    account.linkX509Certificates(singletonList(TEST_0_IAM_X509_CERT));
    accountRepo.save(account);


    Updater u = accountRemovers().x509Certificate(
        newArrayList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT, null, TEST_1_IAM_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testUsernameReplacerWorks() {

    account.setUsername(OLD);
    accountRepo.save(account);

    Updater u = accountReplacers().username(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testActiveReplacerWorks() {

    account.setActive(false);
    accountRepo.save(account);

    Updater u = accountReplacers().active(true);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }


  @Test
  public void testPictureRemoverWorks() {
    account.getUserInfo().setPicture(OLD);
    accountRepo.save(account);

    Updater u = accountRemovers().picture(OLD);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testServiceAccountReplacerWorks() {

    account.setServiceAccount(false);
    accountRepo.save(account);

    Updater u = accountReplacers().serviceAccount(true);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }
}
