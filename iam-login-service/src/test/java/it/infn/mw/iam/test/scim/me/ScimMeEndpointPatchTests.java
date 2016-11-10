package it.infn.mw.iam.test.scim.me;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimMeEndpointPatchTests {

  private ScimRestUtils userRestUtils;
  private ScimUser testUser;

  @Autowired
  private ScimUserProvisioning userService;

  @BeforeClass
  public static void init() {

    JacksonUtils.initRestAssured();
  }

  private ScimUser createTestUser(final String username, final String password,
      final String givenname, final String familyname, final String email) {

    return userService.create(ScimUser.builder()
      .active(true)
      .buildEmail(email)
      .buildName(givenname, familyname)
      .displayName(username)
      .userName(username)
      .password(password)
      .build());
  }

  private void deleteTestUser() {

    userService.delete(testUser.getId());
  }

  @Before
  public void testSetup() {

    testUser =
        createTestUser("johnLennon", "password", "John", "Lennon", "john.lennon@liverpool.uk");
    userRestUtils = ScimRestUtils.getInstance(passwordTokenGetter().username(testUser.getUserName())
      .password("password")
      .getAccessToken());
  }

  @After
  public void testTeardown() {

    deleteTestUser();
  }

  private ScimUser doGet() {

    return userRestUtils.doGet("/scim/Me").extract().as(ScimUser.class);
  }

  private void doPatch(ScimUserPatchRequest patchRequest) {

    userRestUtils.doPatch("/scim/Me", patchRequest);
  }

  @Test
  public void testPatchPassword() {

    final String NEW_PASSWORD = "newpassword";

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().password(NEW_PASSWORD).build())
      .build();

    doPatch(patchRequest);

    // Verify that password has been changed
    passwordTokenGetter().username(testUser.getUserName()).password(NEW_PASSWORD).getAccessToken();
  }

  @Test
  public void testPatchName() {

    final String GIVEN_NAME = "John";
    final String MIDDLE_NAME = "Fitzgerald";
    final String FAMILY_NAME = "Kennedy";

    ScimName updatedName = ScimName.builder()
      .givenName(GIVEN_NAME)
      .middleName(MIDDLE_NAME)
      .familyName(FAMILY_NAME)
      .build();

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().name(updatedName).build()).build();

    doPatch(patchRequest);

    ScimUser updatedUser = doGet();

    Assert.assertThat(updatedUser.getName(), Matchers.equalTo(updatedName));
  }

  @Test
  public void testPatchPicture() {

    final String PICTURE = "http://notarealurl.com/image.jpg";

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().buildPhoto(PICTURE).build()).build();

    doPatch(patchRequest);

    ScimUser updatedUser = doGet();

    Assert.assertThat(updatedUser.getPhotos().get(0).getValue(), Matchers.equalTo(PICTURE));
  }

  @Test
  public void testPatchEmail() {

    final String EMAIL = "john.kennedy@washington.us";

    ScimUserPatchRequest patchRequest =
        ScimUserPatchRequest.builder().add(ScimUser.builder().buildEmail(EMAIL).build()).build();

    doPatch(patchRequest);

    ScimUser updatedUser = doGet();

    Assert.assertThat(updatedUser.getEmails().get(0).getValue(), Matchers.equalTo(EMAIL));
  }

}
