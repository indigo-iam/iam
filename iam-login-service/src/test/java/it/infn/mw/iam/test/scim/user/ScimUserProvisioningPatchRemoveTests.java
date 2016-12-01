package it.infn.mw.iam.test.scim.user;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.ArrayList;
import java.util.List;

import javax.transaction.Transactional;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
@Transactional
public class ScimUserProvisioningPatchRemoveTests {

  private String accessToken;
  private ScimRestUtils restUtils;

  @Autowired
  IamAccountRepository iamAccountRepo;

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
      .addSamlId(ScimSamlId.builder()
        .idpId(TestUtils.samlIds.get(0).idpId)
        .userId(TestUtils.samlIds.get(0).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(TestUtils.x509Certs.get(0).display)
        .value(TestUtils.x509Certs.get(0).certificate)
        .primary(true)
        .build())
      .build()).extract().as(ScimUser.class));

    testUsers.add(restUtils.doPost("/scim/Users/", ScimUser.builder("abraham_lincoln")
      .buildEmail("lincoln@email.test")
      .buildName("Abraham", "Lincoln")
      .addOidcId(ScimOidcId.builder()
        .issuer(TestUtils.oidcIds.get(1).issuer)
        .subject(TestUtils.oidcIds.get(1).subject)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(TestUtils.sshKeys.get(1).key)
        .fingerprint(TestUtils.sshKeys.get(1).fingerprintSHA256)
        .primary(true)
        .build())
      .addSamlId(ScimSamlId.builder()
        .idpId(TestUtils.samlIds.get(1).idpId)
        .userId(TestUtils.samlIds.get(1).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(TestUtils.x509Certs.get(1).display)
        .value(TestUtils.x509Certs.get(1).certificate)
        .primary(true)
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

    restUtils.deleteUsers(testUsers.get(0), testUsers.get(1));
  }

  private ScimUserPatchRequest getPatchRemoveRequest(ScimUser updates) {

    return ScimUserPatchRequest.builder().remove(updates).build();
  }

  @Test
  public void testPatchRemoveOidcId() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addOidcId(user.getIndigoUser().getOidcIds().get(0)).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", equalTo(null));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveAnotherUserOidcId() {

    ScimUser user1 = testUsers.get(0);
    ScimUser user2 = testUsers.get(1);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addOidcId(user2.getIndigoUser().getOidcIds().get(0)).build());

    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
    restUtils.doGet(user2.getMeta().getLocation()).body("id", equalTo(user2.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveNotFoundOidcId() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(ScimUser.builder()
      .addOidcId(ScimOidcId.builder().issuer("fake_issuer").subject("fake_subject").build())
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
  }

  @Test
  public void testPatchRemoveX509Certificate() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addX509Certificate(user.getX509Certificates().get(0)).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    restUtils.doGet(user.getMeta().getLocation())
      .body("id", equalTo(user.getId()))
      .body("x509certificates", equalTo(null));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveAnotherUserX509Certificate() {

    ScimUser user1 = testUsers.get(0);
    ScimUser user2 = testUsers.get(1);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addX509Certificate(user2.getX509Certificates().get(0)).build());

    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doGet(user1.getMeta().getLocation())
      .body("id", equalTo(user1.getId()))
      .body("x509certificates", equalTo(null));
  }


  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveNotFoundX509Certificate() {

    ScimUser user1 = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addX509Certificate(user1.getX509Certificates().get(0)).build());

    restUtils.doPatch(user1.getMeta().getLocation(), req);
    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
  }

  @Test
  public void testPatchRemoveSshKey() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addSshKey(user.getIndigoUser().getSshKeys().get(0)).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys", equalTo(null));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveAnotherUserSshKey() {

    ScimUser user1 = testUsers.get(0);
    ScimUser user2 = testUsers.get(1);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addSshKey(user2.getIndigoUser().getSshKeys().get(0)).build());

    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys", hasSize(equalTo(1)));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveNotFoundSshKey() {

    ScimUser user1 = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addSshKey(user1.getIndigoUser().getSshKeys().get(0)).build());

    restUtils.doPatch(user1.getMeta().getLocation(), req);
    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveSamlId() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addSamlId(user.getIndigoUser().getSamlIds().get(0)).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", equalTo(null));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveAnotherUserSamlId() {

    ScimUser user1 = testUsers.get(0);
    ScimUser user2 = testUsers.get(1);

    ScimUserPatchRequest req = getPatchRemoveRequest(
        ScimUser.builder().addSamlId(user2.getIndigoUser().getSamlIds().get(0)).build());

    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)));
    restUtils.doGet(user2.getMeta().getLocation()).body("id", equalTo(user2.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)));
  }

  @Test
  @Ignore
  @Deprecated
  public void testPatchRemoveNotFoundSamlId() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchRemoveRequest(ScimUser.builder()
      .addSamlId(ScimSamlId.builder().idpId("fake_idpid").userId("fake_userid").build())
      .build());

    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)));
  }
}
