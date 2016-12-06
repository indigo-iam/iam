package it.infn.mw.iam.test.scim.me.patch;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;

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

import com.jayway.restassured.response.ValidatableResponse;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
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
public class ScimMeEndpointPatchAddTests {

  private ScimRestUtils adminRestUtils;
  private ScimRestUtils userRestUtils;

  private final String TESTUSER_USERNAME = "patchAddUser";
  private final String TESTUSER_PASSWORD = "password";
  private final ScimEmail TESTUSER_EMAIL =
      ScimEmail.builder().email("john.lennon@liverpool.uk").build();
  private final ScimName TESTUSER_NAME =
      ScimName.builder().givenName("John").familyName("Lennon").build();
  private final ScimPhoto TESTUSER_PHOTO =
      ScimPhoto.builder().value("http://site.org/user.png").build();

  private ScimUser testUser;

  @BeforeClass
  public static void init() {

    JacksonUtils.initRestAssured();
  }

  @Before
  public void testSetup() {

    adminRestUtils = ScimRestUtils
      .getInstance(TestUtils.getAccessToken("scim-client-rw", "secret", "scim:read scim:write"));

    testUser = adminRestUtils
      .doPost("/scim/Users/",
          ScimUser.builder()
            .active(true)
            .userName(TESTUSER_USERNAME)
            .password(TESTUSER_PASSWORD)
            .addEmail(TESTUSER_EMAIL)
            .name(TESTUSER_NAME)
            .addPhoto(TESTUSER_PHOTO)
            .build())
      .extract()
      .as(ScimUser.class);

    userRestUtils = ScimRestUtils.getInstance(passwordTokenGetter().username(TESTUSER_USERNAME)
      .password(TESTUSER_PASSWORD)
      .getAccessToken());
  }

  @After
  public void testTeardown() {

    adminRestUtils.doDelete(testUser.getMeta().getLocation());
  }

  private ScimUser doGet() {

    return userRestUtils.doGet("/scim/Me").extract().as(ScimUser.class);
  }

  private ValidatableResponse doPatch(ScimUserPatchRequest patchRequest) {

    return doPatch(patchRequest, HttpStatus.NO_CONTENT);
  }

  private ValidatableResponse doPatch(ScimUserPatchRequest patchRequest, HttpStatus expectedHttpStatus) {

    return userRestUtils.doPatch("/scim/Me", patchRequest, expectedHttpStatus);
  }

  @Test
  public void testPatchGivenAndFamilyName() {

    ScimName name = ScimName.builder().givenName("John").familyName("Kennedy").build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().name(name).build()).build();

    doPatch(patchRequest);

    ScimName updatedName = doGet().getName();

    Assert.assertTrue(updatedName.equals(name));
  }

  @Test
  public void testPatchNameNoUpdates() {

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().name(TESTUSER_NAME).build()).build();

    doPatch(patchRequest);

    ScimName updatedName = doGet().getName();

    Assert.assertTrue(updatedName.equals(TESTUSER_NAME));
  }

  @Test
  public void testPatchPicture() {

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().addPhoto(TESTUSER_PHOTO).build())
      .build();

    doPatch(patchRequest);

    ScimPhoto updatedPhoto = doGet().getPhotos().get(0);

    Assert.assertTrue(updatedPhoto.equals(TESTUSER_PHOTO));
  }

  @Test
  public void testPatchPictureNoUpdates() {

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().addPhoto(TESTUSER_PHOTO).build())
      .build();

    doPatch(patchRequest);
    doPatch(patchRequest);

    ScimPhoto updatedPhoto = doGet().getPhotos().get(0);

    Assert.assertTrue(updatedPhoto.equals(TESTUSER_PHOTO));
  }

  @Test
  public void testPatchEmail() {

    final ScimEmail email = ScimEmail.builder().email("john.kennedy@washington.us").build();

    final ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().addEmail(email).build()).build();

    doPatch(patchRequest);

    ScimEmail updatedEmail = doGet().getEmails().get(0);

    Assert.assertTrue(updatedEmail.equals(email));
  }

  @Test
  public void testPatchEmailNoUpdates() {

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().addEmail(TESTUSER_EMAIL).build())
      .build();

    doPatch(patchRequest);

    ScimEmail updatedEmail = doGet().getEmails().get(0);

    Assert.assertTrue(updatedEmail.equals(TESTUSER_EMAIL));
  }

  @Test
  public void testPatchAll() {

    final ScimName NEW_NAME = ScimName.builder().givenName("John").familyName("Kennedy").build();
    final ScimEmail NEW_EMAIL = ScimEmail.builder().email("john.kennedy@washington.us").build();
    final ScimPhoto NEW_PHOTO =
        ScimPhoto.builder().value("http://notarealurl.com/image.jpg").build();

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().name(NEW_NAME).addEmail(NEW_EMAIL).addPhoto(NEW_PHOTO).build())
      .build();

    doPatch(patchRequest);

    ScimUser updatedUser = doGet();

    Assert.assertTrue(updatedUser.getName().equals(NEW_NAME));
    Assert.assertTrue(updatedUser.getPhotos().get(0).equals(NEW_PHOTO));
    Assert.assertTrue(updatedUser.getEmails().get(0).equals(NEW_EMAIL));
  }

  @Test
  public void testPatchAllNoUpdates() {

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder()
        .name(TESTUSER_NAME)
        .addEmail(TESTUSER_EMAIL)
        .addPhoto(TESTUSER_PHOTO)
        .build())
      .build();

    doPatch(patchRequest);

    ScimUser updatedUser = doGet();

    Assert.assertTrue(updatedUser.getName().equals(TESTUSER_NAME));
    Assert.assertTrue(updatedUser.getPhotos().get(0).equals(TESTUSER_PHOTO));
    Assert.assertTrue(updatedUser.getEmails().get(0).equals(TESTUSER_EMAIL));

  }

  @Test
  public void testPatchPasswordNotSupported() {

    final String NEW_PASSWORD = "newpassword";

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().password(NEW_PASSWORD).build())
      .build();

    doPatch(patchRequest, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testPatchAddOidcIdNotSupported() {

    ScimOidcId NEW_TESTUSER_OIDCID =
        ScimOidcId.builder().issuer("new_test_issuer").subject("new_user_subject").build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().addOidcId(NEW_TESTUSER_OIDCID).build()).build();

    doPatch(patchRequest, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testPatchAddSamlIdNotSupported() {

    ScimSamlId TESTUSER_SAMLID =
        ScimSamlId.builder().idpId("AA").userId("BB").build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().addSamlId(TESTUSER_SAMLID).build()).build();

    doPatch(patchRequest, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testPatchAddSsHKeyNotSupported() {

    ScimSshKey NEW_SSH_KEY =
        ScimSshKey.builder().display("ssh-key").value(TestUtils.sshKeys.get(0).key).build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().addSshKey(NEW_SSH_KEY).build()).build();

    doPatch(patchRequest, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testPatchAddX509CertificateNotSupported() {

    ScimX509Certificate NEW_X509_CERT =
        ScimX509Certificate.builder().display("x509-cert").value(TestUtils.x509Certs.get(0).certificate).build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().addX509Certificate(NEW_X509_CERT).build()).build();

    doPatch(patchRequest, HttpStatus.BAD_REQUEST);
  }
}
