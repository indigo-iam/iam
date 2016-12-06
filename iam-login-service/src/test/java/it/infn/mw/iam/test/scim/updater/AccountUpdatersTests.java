package it.infn.mw.iam.test.scim.updater;


import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyString;

import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Adders;
import it.infn.mw.iam.api.scim.updater.builders.Removers;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.api.scim.updater.util.CollectionHelpers;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RunWith(MockitoJUnitRunner.class)
public class AccountUpdatersTests {

  public static final String OLD = "old";
  public static final String NEW = "new";

  public static final IamOidcId OLD_OIDC_ID = new IamOidcId(OLD, OLD);
  public static final IamOidcId NEW_OIDC_ID = new IamOidcId(NEW, NEW);

  public static final IamSamlId OLD_SAML_ID = new IamSamlId(OLD, OLD);
  public static final IamSamlId NEW_SAML_ID = new IamSamlId(NEW, NEW);

  public static final IamSshKey OLD_SSHKEY = new IamSshKey(OLD);
  public static final IamSshKey NEW_SSHKEY = new IamSshKey(NEW);

  public static final IamX509Certificate OLD_X509_CERT = new IamX509Certificate(OLD);
  public static final IamX509Certificate NEW_X509_CERT = new IamX509Certificate(NEW);

  @Mock
  IamAccountRepository repo;

  PasswordEncoder encoder = new BCryptPasswordEncoder();

  IamAccount account;
  IamAccount other;
  IamGroup group;

  private IamAccount newAccount(String username) {
    IamAccount result = new IamAccount();
    result.setUserInfo(new IamUserInfo());

    result.setUsername(username);
    result.setUuid(UUID.randomUUID().toString());
    return result;
  }

  private IamGroup newGroup(String name) {
    IamGroup result = new IamGroup();
    result.setUuid(UUID.randomUUID().toString());
    result.setName(name);
    return result;
  }

  private Adders adder() {
    return AccountUpdaters.adders(repo, encoder, account);
  }

  private Removers removers() {
    return AccountUpdaters.removers(repo, account);
  }

  private Replacers replacers() {
    return AccountUpdaters.replacers(repo, encoder, account);
  }

  @Before
  public void before() {
    account = newAccount("account");
    other = newAccount("other");
    group = newGroup("group");

    Mockito.when(repo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());

    Mockito.when(repo.findBySamlId(anyString(), anyString())).thenReturn(Optional.empty());

    Mockito.when(repo.findByEmail(anyString())).thenReturn(Optional.empty());

    Mockito.when(repo.findBySshKeyValue(anyString())).thenReturn(Optional.empty());

    Mockito.when(repo.findByCertificate(anyString())).thenReturn(Optional.empty());
  }

  private void repoBindOidcIdToAccount(IamOidcId id, IamAccount a) {

    Mockito.when(repo.findByOidcId(id.getIssuer(), id.getSubject())).thenReturn(Optional.of(a));
  }

  private void repoBindSamlIdToAccount(IamSamlId id, IamAccount a) {

    Mockito.when(repo.findBySamlId(id.getIdpId(), id.getUserId())).thenReturn(Optional.of(a));
  }

  private void repoBindEmailToAccount(String email, IamAccount a) {

    Mockito.when(repo.findByEmail(email)).thenReturn(Optional.of(a));
  }

  private void repoBindSshKeyToAccount(IamSshKey key, IamAccount a) {

    Mockito.when(repo.findBySshKeyValue(key.getValue())).thenReturn(Optional.of(a));
  }

  private void repoBindX509CertificateToAccount(IamX509Certificate cert, IamAccount a) {

    Mockito.when(repo.findByCertificate(cert.getCertificate())).thenReturn(Optional.of(a));
  }

  @Test
  public void testCollectionHelperNotNullOrEmpty() {

    new CollectionHelpers();
    assertThat(CollectionHelpers.notNullOrEmpty(Lists.newArrayList()), equalTo(false));
    assertThat(CollectionHelpers.notNullOrEmpty(null), equalTo(false));
  }

  @Test
  public void testUpdatersClass() {

    new AccountUpdaters();
  }

  @Test
  public void testUpdaterType() {

    UpdaterType.valueOf(UpdaterType.ACCOUNT_ADD_OIDC_ID.toString());
  }

  @Test
  public void testPasswordAdderWorks() {

    account.setPassword(encoder.encode(OLD));

    Updater u = adder().password(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }

  @Test
  public void testGivenNameAdderWorks() {

    account.setUserInfo(new IamUserInfo());
    account.getUserInfo().setGivenName(OLD);

    Updater u = adder().givenName(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testFamilyNameAdderWorks() {

    account.getUserInfo().setFamilyName(OLD);

    Updater u = adder().familyName(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test(expected = ScimResourceExistsException.class)
  public void testEmailAdderFailsWhenEmailIsBoundToAnotherUser() {

    account.getUserInfo().setEmail(OLD);
    repoBindEmailToAccount(OLD, account);

    other.getUserInfo().setEmail(NEW);
    repoBindEmailToAccount(NEW, other);

    adder().email(NEW).update();
  }

  @Test
  public void testEmailAdderWorks() {

    account.getUserInfo().setEmail(OLD);

    Mockito.when(repo.findByEmailWithDifferentUUID(NEW, account.getUuid()))
      .thenReturn(Optional.empty());

    Updater u = adder().email(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }

  @Test
  public void testPictureAdderWorks() {
    account.getUserInfo().setPicture(OLD);

    Updater u = adder().picture(NEW);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testPictureAdderWorksForNullValue() {
    account.getUserInfo().setPicture(OLD);

    Updater u = adder().picture(null);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }

  @Test
  public void testOidcIdAdderWorks() {

    Updater u = adder().oidcId(Lists.newArrayList(NEW_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));

  }

  @Test
  public void testOidcIdAdderWorksWithNoUpdate() {

    account.getOidcIds().add(NEW_OIDC_ID);
    repoBindOidcIdToAccount(NEW_OIDC_ID, account);

    Updater u = adder().oidcId(Lists.newArrayList(NEW_OIDC_ID));

    assertThat(u.update(), is(false));

  }

  @Test(expected = ScimResourceExistsException.class)
  public void testOidcIdAdderFailsWhenOidcIdIsLinkedToAnotherAccount() {

    repoBindOidcIdToAccount(NEW_OIDC_ID, other);
    adder().oidcId(Lists.newArrayList(NEW_OIDC_ID)).update();

  }

  @Test
  public void testOidcIdAdderWorksWithUpdate() {

    repoBindOidcIdToAccount(NEW_OIDC_ID, account);

    Updater u = adder().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));

    repoBindOidcIdToAccount(OLD_OIDC_ID, account);

    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));

  }

  @Test
  public void testOidcIdAdderWorksWithListContainingNull() {

    account.getOidcIds().add(NEW_OIDC_ID);
    repoBindOidcIdToAccount(NEW_OIDC_ID, account);

    Updater u = adder().oidcId(newArrayList(NEW_OIDC_ID, null));

    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));

  }

  @Test
  public void testOidcIdAdderWorksWithListContainingDuplicates() {

    account.getOidcIds().add(NEW_OIDC_ID);
    repoBindOidcIdToAccount(NEW_OIDC_ID, account);

    Updater u = adder().oidcId(newArrayList(NEW_OIDC_ID, NEW_OIDC_ID, OLD_OIDC_ID));

    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(2));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID, OLD_OIDC_ID));

  }

  @Test
  public void testOidcIdRemoverWorks() {
    account.getOidcIds().add(NEW_OIDC_ID);
    repoBindOidcIdToAccount(NEW_OIDC_ID, account);

    Updater u = removers().oidcId(newArrayList(NEW_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  public void testOidcIdRemoverWorksWithNoUpdate() {
    account.getOidcIds().add(NEW_OIDC_ID);
    repoBindOidcIdToAccount(NEW_OIDC_ID, account);

    Updater u = removers().oidcId(newArrayList(OLD_OIDC_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(1));
    assertThat(account.getOidcIds(), hasItems(NEW_OIDC_ID));
  }

  @Test
  public void testOidcIdRemoverNoUpdateWithEmptyList() {

    Updater u = removers().oidcId(newArrayList(OLD_OIDC_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(0));

  }

  @Test
  public void testOidcIdRemoverNoUpdateWithEmptyList2() {

    Updater u = removers().oidcId(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getOidcIds(), hasSize(0));

  }

  @Test
  public void testOidcIdRemoverWorksWithMultipleValues() {
    account.getOidcIds().add(NEW_OIDC_ID);
    account.getOidcIds().add(OLD_OIDC_ID);

    Updater u = removers().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));

  }

  @Test
  public void testOidcIdRemoverWorksWithNullAndDuplicatesValues() {
    account.getOidcIds().add(NEW_OIDC_ID);

    Updater u = removers().oidcId(newArrayList(NEW_OIDC_ID, OLD_OIDC_ID, null, OLD_OIDC_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getOidcIds(), hasSize(0));
  }

  @Test
  public void testSamlIdAdderWorks() {

    Updater u = adder().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }

  @Test
  public void testSamlIdAdderWorksWithNoUpdate() {

    account.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, account);

    Updater u = adder().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }


  @Test(expected = ScimResourceExistsException.class)
  public void testSamlIdAdderFailsWhenSamlIdLinkedToAnotherAccount() {
    other.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, other);

    adder().samlId(newArrayList(NEW_SAML_ID)).update();

  }

  @Test
  public void testSamlIdAdderFailsWhenSamlIdLinkedToTheSameAccount() {
    account.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, account);

    Updater u = adder().samlId(newArrayList(NEW_SAML_ID));

    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }

  @Test
  public void testSamlAdderWorksWithListContainingNull() {
    account.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, account);

    Updater u = adder().samlId(newArrayList(NEW_SAML_ID, null, null));
    assertThat(u.update(), is(false));

    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));

  }

  @Test
  public void testSamlAdderWorksWithListContainingDuplicates() {
    account.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, account);

    Updater u = adder().samlId(newArrayList(NEW_SAML_ID, NEW_SAML_ID, OLD_SAML_ID));
    assertThat(u.update(), is(true));

    assertThat(account.getSamlIds(), hasSize(2));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID, OLD_SAML_ID));

  }

  @Test
  public void testSamlRemoverWorks() {
    account.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, account);

    Updater u = removers().samlId(newArrayList(NEW_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));
  }

  @Test
  public void testSamlRemoverWorksWithNoUpdate() {
    account.getSamlIds().add(NEW_SAML_ID);
    repoBindSamlIdToAccount(NEW_SAML_ID, account);

    Updater u = removers().samlId(newArrayList(OLD_SAML_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(1));
    assertThat(account.getSamlIds(), hasItems(NEW_SAML_ID));
  }

  @Test
  public void testSamlRemoverNoUpdateWithEmptyList() {

    Updater u = removers().samlId(newArrayList(OLD_SAML_ID));
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  public void testSamlRemoverNoUpdateWithEmptyList2() {

    Updater u = removers().samlId(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  public void testSamlRemoverWorksWithMultipleValues() {
    account.getSamlIds().add(NEW_SAML_ID);
    account.getSamlIds().add(OLD_SAML_ID);

    Updater u = removers().samlId(newArrayList(NEW_SAML_ID, OLD_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  public void testSamlRemoverWorksWithNullAndDuplicatesValues() {
    account.getSamlIds().add(NEW_SAML_ID);


    Updater u = removers().samlId(newArrayList(NEW_SAML_ID, OLD_SAML_ID, null, OLD_SAML_ID));
    assertThat(u.update(), is(true));
    assertThat(account.getSamlIds(), hasSize(0));

  }

  @Test
  public void testSshKeyAdderWorks() {

    Updater u = adder().sshKey(Lists.newArrayList(NEW_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));

  }

  @Test
  public void testSshKeyAdderWorksWithNoUpdate() {

    account.getSshKeys().add(NEW_SSHKEY);
    repoBindSshKeyToAccount(NEW_SSHKEY, account);

    Updater u = adder().sshKey(Lists.newArrayList(NEW_SSHKEY));

    assertThat(u.update(), is(false));

  }

  @Test(expected = ScimResourceExistsException.class)
  public void testSshKeyAdderFailsWhenSshKeyIsLinkedToAnotherAccount() {

    repoBindSshKeyToAccount(NEW_SSHKEY, other);
    adder().sshKey(Lists.newArrayList(NEW_SSHKEY)).update();

  }

  @Test
  public void testSshKeyAdderWorksWithUpdate() {

    repoBindSshKeyToAccount(NEW_SSHKEY, account);

    Updater u = adder().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));

    repoBindSshKeyToAccount(OLD_SSHKEY, account);

    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));

  }

  @Test
  public void testSshKeyAdderWorksWithListContainingNull() {

    account.getSshKeys().add(NEW_SSHKEY);
    repoBindSshKeyToAccount(NEW_SSHKEY, account);

    Updater u = adder().sshKey(newArrayList(NEW_SSHKEY, null));

    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));

  }

  @Test
  public void testSshKeyAdderWorksWithListContainingDuplicates() {

    account.getSshKeys().add(NEW_SSHKEY);
    repoBindSshKeyToAccount(NEW_SSHKEY, account);

    Updater u = adder().sshKey(newArrayList(NEW_SSHKEY, NEW_SSHKEY, OLD_SSHKEY));

    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(2));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY, OLD_SSHKEY));

  }

  @Test
  public void testSshKeyRemoverWorks() {

    account.getSshKeys().add(NEW_SSHKEY);
    repoBindSshKeyToAccount(NEW_SSHKEY, account);

    Updater u = removers().sshKey(newArrayList(NEW_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));
  }

  @Test
  public void testSshKeyRemoverWorksWithNoUpdate() {
    account.getSshKeys().add(NEW_SSHKEY);
    repoBindSshKeyToAccount(NEW_SSHKEY, account);

    Updater u = removers().sshKey(newArrayList(OLD_SSHKEY));
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(1));
    assertThat(account.getSshKeys(), hasItems(NEW_SSHKEY));
  }

  @Test
  public void testSshKeyRemoverNoUpdateWithEmptyList() {

    Updater u = removers().sshKey(newArrayList(OLD_SSHKEY));
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testSshKeyRemoverNoUpdateWithEmptyList2() {

    Updater u = removers().sshKey(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testSshKeyRemoverWorksWithMultipleValues() {
    account.getSshKeys().add(NEW_SSHKEY);
    account.getSshKeys().add(OLD_SSHKEY);

    Updater u = removers().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testSshKeyRemoverWorksWithNullAndDuplicatesValues() {
    account.getSshKeys().add(NEW_SSHKEY);

    Updater u = removers().sshKey(newArrayList(NEW_SSHKEY, OLD_SSHKEY, null, OLD_SSHKEY));
    assertThat(u.update(), is(true));
    assertThat(account.getSshKeys(), hasSize(0));

  }

  @Test
  public void testX509CertificateAdderWorks() {

    Updater u = adder().x509Certificate(Lists.newArrayList(NEW_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(NEW_X509_CERT));

  }

  @Test
  public void testX509CertificateAdderWorksWithNoUpdate() {

    account.getX509Certificates().add(NEW_X509_CERT);
    repoBindX509CertificateToAccount(NEW_X509_CERT, account);

    Updater u = adder().x509Certificate(Lists.newArrayList(NEW_X509_CERT));

    assertThat(u.update(), is(false));

  }

  @Test(expected = ScimResourceExistsException.class)
  public void testX509CertificateAdderFailsWhenX509CertificateIsLinkedToAnotherAccount() {

    repoBindX509CertificateToAccount(NEW_X509_CERT, other);
    adder().x509Certificate(Lists.newArrayList(NEW_X509_CERT)).update();

  }

  @Test
  public void testX509CertificateAdderWorksWithUpdate() {

    repoBindX509CertificateToAccount(NEW_X509_CERT, account);

    Updater u = adder().x509Certificate(newArrayList(NEW_X509_CERT, OLD_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(NEW_X509_CERT, OLD_X509_CERT));

    repoBindX509CertificateToAccount(OLD_X509_CERT, account);

    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(NEW_X509_CERT, OLD_X509_CERT));

  }

  @Test
  public void testX509CertificateAdderWorksWithListContainingNull() {

    account.getX509Certificates().add(NEW_X509_CERT);
    repoBindX509CertificateToAccount(NEW_X509_CERT, account);

    Updater u = adder().x509Certificate(newArrayList(NEW_X509_CERT, null));

    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(NEW_X509_CERT));

  }

  @Test
  public void testX509CertificateAdderWorksWithListContainingDuplicates() {

    account.getX509Certificates().add(NEW_X509_CERT);
    repoBindX509CertificateToAccount(NEW_X509_CERT, account);

    Updater u = adder().x509Certificate(newArrayList(NEW_X509_CERT, NEW_X509_CERT, OLD_X509_CERT));

    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(2));
    assertThat(account.getX509Certificates(), hasItems(NEW_X509_CERT, OLD_X509_CERT));

  }

  @Test
  public void testX509CertificateRemoverWorks() {

    account.getX509Certificates().add(NEW_X509_CERT);
    repoBindX509CertificateToAccount(NEW_X509_CERT, account);

    Updater u = removers().x509Certificate(newArrayList(NEW_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));
  }

  @Test
  public void testX509CertificateRemoverWorksWithNoUpdate() {
    account.getX509Certificates().add(NEW_X509_CERT);
    repoBindX509CertificateToAccount(NEW_X509_CERT, account);

    Updater u = removers().x509Certificate(newArrayList(OLD_X509_CERT));
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(1));
    assertThat(account.getX509Certificates(), hasItems(NEW_X509_CERT));
  }

  @Test
  public void testX509CertificateRemoverNoUpdateWithEmptyList() {

    Updater u = removers().x509Certificate(newArrayList(OLD_X509_CERT));
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testX509CertificateRemoverNoUpdateWithEmptyList2() {

    Updater u = removers().x509Certificate(newArrayList());
    assertThat(u.update(), is(false));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testX509CertificateRemoverWorksWithMultipleValues() {
    account.getX509Certificates().add(NEW_X509_CERT);
    account.getX509Certificates().add(OLD_X509_CERT);

    Updater u = removers().x509Certificate(newArrayList(NEW_X509_CERT, OLD_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testX509CertificateRemoverWorksWithNullAndDuplicatesValues() {
    account.getX509Certificates().add(NEW_X509_CERT);

    Updater u =
        removers().x509Certificate(newArrayList(NEW_X509_CERT, OLD_X509_CERT, null, OLD_X509_CERT));
    assertThat(u.update(), is(true));
    assertThat(account.getX509Certificates(), hasSize(0));

  }

  @Test
  public void testUsernameReplacerWorks() {

    account.setUsername(OLD);

    Mockito.when(repo.findByUsername(NEW)).thenReturn(Optional.empty());

    Updater u = replacers().username(NEW);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }

  @Test
  public void testActiveReplacerWorks() {

    account.setActive(false);

    Updater u = replacers().active(true);
    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

  }

  @Test
  public void testGroupMembershipAdderWorks() {

    Updater u = adder().group(Lists.newArrayList(group));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getGroups(), hasSize(1));
    assertThat(account.getGroups(), hasItems(group));
  }

  @Test
  public void testGroupMembershipRemoverWorks() {

    account.setGroups(Sets.newHashSet(group));
    Updater u = removers().group(Lists.newArrayList(group));

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));

    assertThat(account.getGroups(), hasSize(0));
  }

  @Test
  public void testPictureRemoverWorks() {
    account.getUserInfo().setPicture(OLD);

    Updater u = removers().picture(OLD);

    assertThat(u.update(), is(true));
    assertThat(u.update(), is(false));
  }
}
