package it.infn.mw.iam.test.scim.user;

import static org.hamcrest.Matchers.containsString;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimUserProvisioningPatchReplaceTests {

  private String accessToken;
  private ScimRestUtils restUtils;

  private List<ScimUser> testUsers = new ArrayList<ScimUser>();

  @BeforeClass
  public static void init() {

    JacksonUtils.initRestAssured();
  }

  private void initTestUsers() {

    testUsers.add(restUtils.doPost("/scim/Users/", ScimUser.builder("john_lennon")
      .buildEmail("lennon@email.test")
      .buildName("John", "Lennon")
      .addOidcId(ScimOidcId.builder()
        .issuer(TestUtils.oidcIds.get(0).issuer)
        .subject(TestUtils.oidcIds.get(0).subject)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(TestUtils.sshKeys.get(0).key)
        .fingerprint(TestUtils.sshKeys.get(0).fingerprintSHA256)
        .primary(true)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(TestUtils.sshKeys.get(1).key)
        .fingerprint(TestUtils.sshKeys.get(1).fingerprintSHA256)
        .primary(false)
        .build())
      .addSamlId(ScimSamlId.builder()
        .idpId(TestUtils.samlIds.get(0).idpId)
        .userId(TestUtils.samlIds.get(0).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(TestUtils.x509Certs.get(0).display)
        .value(TestUtils.x509Certs.get(0).certificate)
        .primary(true)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(TestUtils.x509Certs.get(1).display)
        .value(TestUtils.x509Certs.get(1).certificate)
        .primary(false)
        .build())
      .build()).extract().as(ScimUser.class));
  }

  @Before
  public void setupTest() {

    accessToken = TestUtils.getAccessToken("scim-client-rw", "secret", "scim:read scim:write");
    restUtils = ScimRestUtils.getInstance(accessToken);

    initTestUsers();
  }

  @After
  public void teardownTest() {

    testUsers.forEach(user -> restUtils.doDelete(user.getMeta().getLocation()));
  }

  private ScimUserPatchRequest getPatchReplaceRequest(ScimUser updates) {

    return ScimUserPatchRequest.builder().replace(updates).build();
  }

  @Test
  public void testPatchReplaceX509CertificateDisplay() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(ScimUser.builder()
      .buildX509Certificate(user.getX509Certificates().get(0).getDisplay() + "_updated",
          user.getX509Certificates().get(0).getValue(), null)
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);

    Assert
      .assertTrue(updated_user.getX509Certificates()
        .stream()
        .filter(cert -> cert.getValue().equals(user.getX509Certificates().get(0).getValue()) && cert
          .getDisplay().equals(user.getX509Certificates().get(0).getDisplay() + "_updated"))
        .findFirst()
        .isPresent());
  }

  @Test
  public void testPatchReplaceX509CertificatePrimary() {

    ScimUser user = testUsers.get(0);

    ScimX509Certificate certToReplace = user.getX509Certificates().get(0);
    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildX509Certificate(null, certToReplace.getValue(), false).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);
    Assert.assertTrue(
        updated_user.getX509Certificates().stream().filter(cert -> cert.isPrimary()).count() == 1);
  }

  @Test
  public void testPatchReplaceX509CertificatePrimarySwitch() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(ScimUser.builder()
      .buildX509Certificate(null, user.getX509Certificates().get(0).getValue(), false)
      .buildX509Certificate(null, user.getX509Certificates().get(1).getValue(), true)
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);

    Assert.assertTrue(updated_user.getX509Certificates()
      .stream()
      .filter(cert -> cert.getValue().equals(user.getX509Certificates().get(0).getValue())
          && !cert.isPrimary())
      .findFirst()
      .isPresent());

    Assert.assertTrue(updated_user.getX509Certificates()
      .stream()
      .filter(cert -> cert.getValue().equals(user.getX509Certificates().get(1).getValue())
          && cert.isPrimary())
      .findFirst()
      .isPresent());
  }

  @Test
  public void testPatchReplaceX509CertificateNotFound() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildX509Certificate("fake_display", "fake_value", true).build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
  }

  @Test
  public void testPatchReplaceSshKeyDisplay() {

    ScimUser user = testUsers.get(0);

    ScimSshKey sshKeyToReplace = user.getIndigoUser().getSshKeys().get(0);
    ScimUserPatchRequest req = getPatchReplaceRequest(ScimUser.builder()
      .buildSshKey("New ssh key label", sshKeyToReplace.getValue(),
          sshKeyToReplace.getFingerprint(), sshKeyToReplace.isPrimary())
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);

    Assert.assertTrue(updated_user.getIndigoUser()
      .getSshKeys()
      .stream()
      .filter(sshKey -> sshKey.getValue().equals(sshKeyToReplace.getValue())
          && sshKey.getDisplay().equals("New ssh key label"))
      .findFirst()
      .isPresent());
  }

  @Test
  public void testPatchReplaceSshKeyPrimary() {

    ScimUser user = testUsers.get(0);

    ScimSshKey keyToReplace = user.getIndigoUser().getSshKeys().get(0);
    ScimUserPatchRequest req = getPatchReplaceRequest(ScimUser.builder()
      .buildSshKey(keyToReplace.getDisplay(), keyToReplace.getValue(),
          keyToReplace.getFingerprint(), false)
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);

    Assert.assertTrue(updated_user.getIndigoUser()
      .getSshKeys()
      .stream()
      .filter(sshKey -> sshKey.isPrimary())
      .count() == 1);
  }

  @Test
  public void testPatchReplaceSshKeyPrimarySwitch() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(ScimUser.builder()
      .buildSshKey(null, user.getIndigoUser().getSshKeys().get(0).getValue(), null, false)
      .buildSshKey(null, user.getIndigoUser().getSshKeys().get(1).getValue(), null, true)
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);

    Assert.assertTrue(
        updated_user.getIndigoUser()
          .getSshKeys()
          .stream()
          .filter(sshKey -> sshKey.getValue()
            .equals(user.getIndigoUser().getSshKeys().get(0).getValue()) && !sshKey.isPrimary())
          .findFirst()
          .isPresent());

    Assert.assertTrue(
        updated_user.getIndigoUser()
          .getSshKeys()
          .stream()
          .filter(sshKey -> sshKey.getValue()
            .equals(user.getIndigoUser().getSshKeys().get(1).getValue()) && sshKey.isPrimary())
          .findFirst()
          .isPresent());
  }

  @Test
  public void testPatchReplaceSshKeyNotFound() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildSshKey("fake_label", "fake_key", "fake_fingerprint", true).build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
  }


  @Test
  public void testReplaceEmailWithEmptyValue() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildEmail("").build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.BAD_REQUEST).body("detail",
        containsString("scimUserPatchRequest.operations[0].value.emails[0].value : may not be empty"));
  }

  @Test
  public void testReplaceEmailWithNullValue() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildEmail(null).build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.BAD_REQUEST).body("detail",
        containsString("scimUserPatchRequest.operations[0].value.emails[0].value : may not be empty"));
  }

  @Test
  public void testReplaceEmailWithSameValue() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildEmail(user.getEmails().get(0).getValue()).build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NO_CONTENT);
  }

  @Test
  public void testReplaceEmailWithInvalidValue() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchReplaceRequest(
        ScimUser.builder().buildEmail("fakeEmail").build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.BAD_REQUEST).body("detail",
        containsString("scimUserPatchRequest.operations[0].value.emails[0].value : not a well-formed email address"));;
  }
}
