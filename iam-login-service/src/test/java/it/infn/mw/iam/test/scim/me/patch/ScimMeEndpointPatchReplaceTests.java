package it.infn.mw.iam.test.scim.me.patch;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.equalTo;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimMeEndpointPatchReplaceTests {

  private ScimRestUtils adminRestUtils;
  private ScimRestUtils userRestUtils;
  private ScimUser testUser;

  final String ANOTHERUSER_USERNAME = "test";
  final ScimEmail ANOTHERUSER_EMAIL = ScimEmail.builder().email("test@iam.test").build();

  final String TESTUSER_USERNAME = "patchReplaceUser";
  final String TESTUSER_PASSWORD = "password";
  final ScimName TESTUSER_NAME = ScimName.builder().givenName("John").familyName("Lennon").build();
  final ScimEmail TESTUSER_EMAIL = ScimEmail.builder().email("john.lennon@liverpool.uk").build();
  final ScimPhoto TESTUSER_PHOTO = ScimPhoto.builder().value("http://site.org/user.png").build();

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
      .extract().as(ScimUser.class);

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

  private void doPatch(ScimUserPatchRequest patchRequest) {

    userRestUtils.doPatch("/scim/Me", patchRequest);
  }

  @Test
  @Ignore
  public void testPatchReplacePassword() {

    final String NEW_PASSWORD = "newpassword";

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().password(NEW_PASSWORD).build())
      .build();

    doPatch(patchRequest);

    // Verify that password has been changed
    passwordTokenGetter().username(TESTUSER_USERNAME).password(NEW_PASSWORD).getAccessToken();
  }

  @Test
  @Ignore
  public void testPatchReplacePasswordNoUpdates() {

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().password(TESTUSER_PASSWORD).build())
      .build();

    doPatch(patchRequest);

    passwordTokenGetter().username(TESTUSER_USERNAME).password(TESTUSER_PASSWORD).getAccessToken();
  }

  @Test
  public void testPatchReplaceGivenAndFamilyName() {

    ScimName name =
        ScimName.builder().givenName("John").familyName("Kennedy").build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().replace(ScimUser.builder().name(name).build()).build();

    doPatch(patchRequest);

    ScimName updatedName = doGet().getName();

    Assert.assertTrue(updatedName.equals(name));
  }

  @Test
  public void testPatchReplaceNameNoUpdates() {

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().name(TESTUSER_NAME).build())
      .build();

    doPatch(patchRequest);

    ScimName updatedName = doGet().getName();

    Assert.assertTrue(updatedName.equals(TESTUSER_NAME));
  }

  @Test
  public void testPatchReplacePicture() {

    final ScimPhoto newPhoto = ScimPhoto.builder().value("http://site.org/user2.png").build();

    final ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().addPhoto(newPhoto).build()).build();

    doPatch(patchRequest);

    ScimPhoto updatedPhoto = doGet().getPhotos().get(0);

    Assert.assertTrue(updatedPhoto.equals(newPhoto));
  }

  @Test
  public void testPatchReplacePictureNoUpdates() {

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().addPhoto(TESTUSER_PHOTO).build())
      .build();

    doPatch(patchRequest);

    ScimPhoto updatedPhoto = doGet().getPhotos().get(0);

    Assert.assertTrue(updatedPhoto.equals(TESTUSER_PHOTO));
  }

  @Test
  public void testPatchReplaceEmail() {

    final ScimEmail email = ScimEmail.builder().email("john.kennedy@washington.us").build();

    final ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().replace(ScimUser.builder().addEmail(email).build()).build();

    doPatch(patchRequest);

    ScimEmail updatedEmail = doGet().getEmails().get(0);

    Assert.assertTrue(updatedEmail.equals(email));
  }

  @Test
  public void testPatchReplaceAlreadyUsedEmail() {

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().addEmail(ANOTHERUSER_EMAIL).build())
      .build();

    userRestUtils.doPatch(testUser.getMeta().getLocation(), patchRequest, HttpStatus.CONFLICT)
      .body("status", equalTo("409"))
      .body("detail", containsString("already bound to another user"));
  }

  @Test
  public void testPatchReplaceEmailNoUpdates() {

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder().addEmail(TESTUSER_EMAIL).build())
      .build();

    doPatch(patchRequest);

    ScimEmail updatedEmail = doGet().getEmails().get(0);

    Assert.assertTrue(updatedEmail.equals(TESTUSER_EMAIL));
  }

  @Test
  public void testPatchReplaceAll() {

    final ScimName NEW_NAME =
        ScimName.builder().givenName("John").familyName("Kennedy").build();

    final ScimEmail NEW_EMAIL = ScimEmail.builder().email("john.kennedy@washington.us").build();
    final ScimPhoto NEW_PHOTO =
        ScimPhoto.builder().value("http://notarealurl.com/image.jpg").build();

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder()
        .name(NEW_NAME)
        .addEmail(NEW_EMAIL)
        .addPhoto(NEW_PHOTO)
        .build())
      .build();

    doPatch(patchRequest);

    ScimUser updatedUser = doGet();

    Assert.assertTrue(updatedUser.getName().equals(NEW_NAME));
    Assert.assertTrue(updatedUser.getPhotos().get(0).equals(NEW_PHOTO));
    Assert.assertTrue(updatedUser.getEmails().get(0).equals(NEW_EMAIL));
  }

  @Test
  public void testPatchReplaceAllNoUpdates() {

    final ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .replace(ScimUser.builder()
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
}
