package it.infn.mw.iam.test.scim.core.provisioning.user;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@Transactional
public class ScimUserProvisioningTests {

  @Autowired
  private ScimUserProvisioning userService;

  @Autowired
  private PasswordEncoder passwordEncoder;

  final String TESTUSER_USERNAME = "testProvisioningUser";
  final String TESTUSER_PASSWORD = "password";
  final ScimName TESTUSER_NAME = ScimName.builder().givenName("John").familyName("Lennon").build();
  final ScimEmail TESTUSER_EMAIL = ScimEmail.builder().email("john.lennon@liverpool.uk").build();
  final ScimPhoto TESTUSER_PHOTO = ScimPhoto.builder().value("http://site.org/user.png").build();
  final ScimOidcId TESTUSER_OIDCID =
      ScimOidcId.builder().issuer("urn:oidc:test:issuer").subject("1234").build();
  final ScimSamlId TESTUSER_SAMLID = ScimSamlId.builder().idpId("idpID").userId("userId").build();
  final ScimSshKey TESTUSER_SSHKEY = ScimSshKey.builder()
    .primary(true)
    .display("Personal Key")
    .value(TestUtils.sshKeys.get(0).key)
    .build();
  final ScimX509Certificate TESTUSER_X509CERT = ScimX509Certificate.builder()
    .display("Personal X509 Certificate")
    .value(TestUtils.x509Certs.get(0).certificate)
    .primary(true)
    .build();

  @Test
  public void createUserTest() {

    ScimUser scimUser = ScimUser.builder()
      .active(true)
      .userName(TESTUSER_USERNAME)
      .password(TESTUSER_PASSWORD)
      .name(TESTUSER_NAME)
      .addEmail(TESTUSER_EMAIL)
      .addPhoto(TESTUSER_PHOTO)
      .addOidcId(TESTUSER_OIDCID)
      .addSamlId(TESTUSER_SAMLID)
      .addSshKey(TESTUSER_SSHKEY)
      .addX509Certificate(TESTUSER_X509CERT)
      .build();

    IamAccount iamAccount = userService.createAccount(scimUser);

    Assert.assertNotNull(iamAccount);

    Assert.assertTrue(iamAccount.isActive());

    Assert.assertThat(iamAccount.getUsername(), Matchers.equalTo(TESTUSER_USERNAME));

    Assert.assertTrue(passwordEncoder.matches(TESTUSER_PASSWORD, iamAccount.getPassword()));

    Assert.assertThat(iamAccount.getUserInfo().getGivenName(),
        Matchers.equalTo(TESTUSER_NAME.getGivenName()));
    Assert.assertThat(iamAccount.getUserInfo().getMiddleName(),
        Matchers.equalTo(TESTUSER_NAME.getMiddleName()));
    Assert.assertThat(iamAccount.getUserInfo().getFamilyName(),
        Matchers.equalTo(TESTUSER_NAME.getFamilyName()));

    Assert.assertThat(iamAccount.getUserInfo().getPicture(),
        Matchers.equalTo(TESTUSER_PHOTO.getValue()));

    Assert.assertThat(iamAccount.getUserInfo().getEmail(),
        Matchers.equalTo(TESTUSER_EMAIL.getValue()));

    Assert.assertThat(iamAccount.getOidcIds().get(0).getIssuer(),
        Matchers.equalTo(TESTUSER_OIDCID.getIssuer()));
    Assert.assertThat(iamAccount.getOidcIds().get(0).getSubject(),
        Matchers.equalTo(TESTUSER_OIDCID.getSubject()));

    Assert.assertThat(iamAccount.getSamlIds().get(0).getIdpId(),
        Matchers.equalTo(TESTUSER_SAMLID.getIdpId()));
    Assert.assertThat(iamAccount.getSamlIds().get(0).getUserId(),
        Matchers.equalTo(TESTUSER_SAMLID.getUserId()));

    Assert.assertThat(iamAccount.getSshKeys().get(0).getLabel(),
        Matchers.equalTo(TESTUSER_SSHKEY.getDisplay()));
    Assert.assertThat(iamAccount.getSshKeys().get(0).getFingerprint(),
        Matchers.equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256));
    Assert.assertThat(iamAccount.getSshKeys().get(0).getValue(),
        Matchers.equalTo(TESTUSER_SSHKEY.getValue()));
    Assert.assertThat(iamAccount.getSshKeys().get(0).isPrimary(),
        Matchers.equalTo(TESTUSER_SSHKEY.isPrimary()));

    Assert.assertThat(iamAccount.getX509Certificates().get(0).getLabel(),
        Matchers.equalTo(TESTUSER_X509CERT.getDisplay()));
    Assert.assertThat(iamAccount.getX509Certificates().get(0).getCertificate(),
        Matchers.equalTo(TESTUSER_X509CERT.getValue()));
    Assert.assertThat(iamAccount.getX509Certificates().get(0).isPrimary(),
        Matchers.equalTo(TESTUSER_X509CERT.isPrimary()));

    userService.delete(iamAccount.getUuid());
  }
}
