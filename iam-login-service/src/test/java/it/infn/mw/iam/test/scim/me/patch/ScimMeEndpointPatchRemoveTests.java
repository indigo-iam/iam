package it.infn.mw.iam.test.scim.me.patch;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimMeEndpointPatchRemoveTests {

  private ScimRestUtils userRestUtils;
  private ScimRestUtils adminRestUtils;
  private ScimUser testUser;

  final String TESTUSER_USERNAME = "patchRemoveUser";
  final String TESTUSER_PASSWORD = "password";
  final ScimName TESTUSER_NAME = ScimName.builder().givenName("John").familyName("Lennon").build();
  final ScimEmail TESTUSER_EMAIL = ScimEmail.builder().email("john.lennon@liverpool.uk").build();
  final ScimPhoto TESTUSER_PHOTO = ScimPhoto.builder().value("http://site.org/user.png").build();
  final ScimOidcId TESTUSER_OIDCID =
      ScimOidcId.builder().issuer("OIDC_ID_ISSUER").subject("OIDC_ID_SUBJECT").build();
  final ScimSamlId TESTUSER_SAMLID =
      ScimSamlId.builder().idpId("SAML_ID_IDP").userId("SAML_ID_USER").build();

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
            .addOidcId(TESTUSER_OIDCID)
            .addSamlId(TESTUSER_SAMLID)
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

  private void doPatch(ScimUserPatchRequest patchRequest) {

    userRestUtils.doPatch("/scim/Me", patchRequest);
  }

  @Test
  public void testPatchRemovePicture() {

    final ScimUserPatchRequest patchAddRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().addPhoto(TESTUSER_PHOTO).build())
      .build();

    doPatch(patchAddRequest);

    ScimPhoto updatedPhoto = doGet().getPhotos().get(0);

    Assert.assertTrue(updatedPhoto.equals(TESTUSER_PHOTO));

    ScimUserPatchRequest patchRemoveRequest = ScimUserPatchRequest.builder()
      .remove(ScimUser.builder().addPhoto(TESTUSER_PHOTO).build())
      .build();

    doPatch(patchRemoveRequest);

    ScimUser updatedUser = doGet();

    Assert.assertFalse(updatedUser.hasPhotos());
  }

  @Test
  public void testPatchRemoveOidcId() {

    final ScimUserPatchRequest patchRemoveRequest = ScimUserPatchRequest.builder()
      .remove(ScimUser.builder().addOidcId(TESTUSER_OIDCID).build())
      .build();

    doPatch(patchRemoveRequest);

    ScimUser updatedUser = doGet();

    assertThat(updatedUser.hasOidcIds(), equalTo(false));
  }

  @Test
  public void testPatchRemoveSamlId() {

    final ScimUserPatchRequest patchRemoveRequest = ScimUserPatchRequest.builder()
      .remove(ScimUser.builder().addSamlId(TESTUSER_SAMLID).build())
      .build();

    doPatch(patchRemoveRequest);

    ScimUser updatedUser = doGet();

    assertThat(updatedUser.hasSamlIds(), equalTo(false));
  }

}
