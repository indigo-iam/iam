package it.infn.mw.iam.test.scim.user;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimUserProvisioningPatchAddTests {

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
      .build()).extract().as(ScimUser.class));

    testUsers.add(restUtils.doPost("/scim/Users/", ScimUser.builder("abraham_lincoln")
      .buildEmail("lincoln@email.test")
      .buildName("Abraham", "Lincoln")
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

//  private ScimUserPatchRequest getPatchRemoveRequest(ScimUser updates) {
//
//    return ScimUserPatchRequest.builder().remove(updates).build();
//  }

  private ScimUserPatchRequest getPatchAddRequest(ScimUser updates) {

    return ScimUserPatchRequest.builder().add(updates).build();
  }

  @Test
  public void testPatchAddOidcId() {

    ScimUser user = testUsers.get(0);

    ScimUserPatchRequest req = getPatchAddRequest(
        ScimUser.builder().buildOidcId(TestUtils.oidcIds.get(0).issuer, TestUtils.oidcIds.get(0).subject).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updated_user =
        restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);
  
//    Assert
//    
//        .body("id", equalTo(user.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
  }

//  @Test
//  public void testPatchRemoveAnotherUserOidcId() {
//
//    ScimUser user1 = testUsers.get(0);
//    ScimUser user2 = testUsers.get(1);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addOidcId(user2.getIndigoUser().getOidcIds().get(0)).build());
//
//    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//
//    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
//    restUtils.doGet(user2.getMeta().getLocation()).body("id", equalTo(user2.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
//  }
//
//  @Test
//  public void testPatchRemoveNotFoundOidcId() {
//
//    ScimUser user = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(ScimUser.builder()
//      .addOidcId(ScimOidcId.builder().issuer("fake_issuer").subject("fake_subject").build())
//      .build());
//
//    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//
//    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)));
//  }
//
//  @Test
//  public void testPatchRemoveX509Certificate() {
//
//    ScimUser user = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addX509Certificate(user.getX509Certificates().get(0)).build());
//
//    restUtils.doPatch(user.getMeta().getLocation(), req);
//
//    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
//        "x509certificates", equalTo(null));
//  }
//
//  @Test
//  public void testPatchRemoveAnotherUserX509Certificate() {
//
//    ScimUser user1 = testUsers.get(0);
//    ScimUser user2 = testUsers.get(1);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addX509Certificate(user2.getX509Certificates().get(0)).build());
//
//    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//
//    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
//        "x509certificates", equalTo(null));
//  }
//
//
//  @Test
//  public void testPatchRemoveNotFoundX509Certificate() {
//
//    ScimUser user1 = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addX509Certificate(user1.getX509Certificates().get(0)).build());
//
//    restUtils.doPatch(user1.getMeta().getLocation(), req);
//    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//  }
//  
//  @Test
//  public void testPatchRemoveSshKey() {
//
//    ScimUser user = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addSshKey(user.getIndigoUser().getSshKeys().get(0)).build());
//
//    restUtils.doPatch(user.getMeta().getLocation(), req);
//
//    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys", equalTo(null));
//  }
//  
//  @Test
//  public void testPatchRemoveAnotherUserSshKey() {
//
//    ScimUser user1 = testUsers.get(0);
//    ScimUser user2 = testUsers.get(1);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addSshKey(user2.getIndigoUser().getSshKeys().get(0)).build());
//
//    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//
//    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys", hasSize(equalTo(1)));
//  }
//
//  @Test
//  public void testPatchRemoveNotFoundSshKey() {
//
//    ScimUser user1 = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addSshKey(user1.getIndigoUser().getSshKeys().get(0)).build());
//
//    restUtils.doPatch(user1.getMeta().getLocation(), req);
//    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//  }
//  
//  @Test
//  public void testPatchRemoveSamlId() {
//
//    ScimUser user = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addSamlId(user.getIndigoUser().getSamlIds().get(0)).build());
//
//    restUtils.doPatch(user.getMeta().getLocation(), req);
//
//    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", equalTo(null));
//  }
//
//  @Test
//  public void testPatchRemoveAnotherUserSamlId() {
//
//    ScimUser user1 = testUsers.get(0);
//    ScimUser user2 = testUsers.get(1);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(
//        ScimUser.builder().addSamlId(user2.getIndigoUser().getSamlIds().get(0)).build());
//
//    restUtils.doPatch(user1.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//
//    restUtils.doGet(user1.getMeta().getLocation()).body("id", equalTo(user1.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)));
//    restUtils.doGet(user2.getMeta().getLocation()).body("id", equalTo(user2.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)));
//  }
//
//  @Test
//  public void testPatchRemoveNotFoundSamlId() {
//
//    ScimUser user = testUsers.get(0);
//
//    ScimUserPatchRequest req = getPatchRemoveRequest(ScimUser.builder()
//      .addSamlId(ScimSamlId.builder().idpId("fake_idpid").userId("fake_userid").build())
//      .build());
//
//    restUtils.doPatch(user.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);
//
//    restUtils.doGet(user.getMeta().getLocation()).body("id", equalTo(user.getId())).body(
//        ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)));
//  }
}
