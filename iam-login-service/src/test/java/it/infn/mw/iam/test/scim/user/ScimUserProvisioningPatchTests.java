package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.Base64;

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
import it.infn.mw.iam.api.scim.model.ScimAddress;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimUserProvisioningPatchTests {

  private String accessToken;
  private ScimRestUtils restUtils;

  @BeforeClass
  public static void init() {

    JacksonUtils.initRestAssured();
  }

  @Before
  public void initAccessToken() {

    accessToken = TestUtils.getAccessToken("scim-client-rw", "secret", "scim:read scim:write");
    restUtils = ScimRestUtils.getInstance(accessToken);
  }

  private ScimUser addTestUser(final String userName, final String email, final String firstName,
      final String LastName) {

    return restUtils
      .doPost("/scim/Users/",
          ScimUser.builder(userName)
            .buildEmail(email)
            .buildName(firstName, LastName)
            .active(true)
            .build())
      .extract().as(ScimUser.class);
  }

  private ScimUserPatchRequest getPatchAddRequest(final ScimUser updates) {

    return ScimUserPatchRequest.builder().add(updates).build();
  }

  private ScimUserPatchRequest getPatchRemoveRequest(final ScimUser updates) {

    return ScimUserPatchRequest.builder().remove(updates).build();
  }

  private ScimUserPatchRequest getPatchReplaceRequest(final ScimUser updates) {

    return ScimUserPatchRequest.builder().replace(updates).build();
  }

  @Test
  public void testPatchUserInfo() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimAddress address = ScimAddress.builder()
      .country("IT")
      .formatted("viale Berti Pichat 6/2\nBologna IT")
      .locality("Bologna")
      .postalCode("40121")
      .region("Emilia Romagna")
      .streetAddress("viale Berti Pichat")
      .build();

    ScimName name = ScimName.builder()
      .givenName("John jr.")
      .familyName("Lennon II")
      .middleName("Francis")
      .build();

    /*
     * Update: - email - username - active - name - address
     */
    ScimUser lennon_update = ScimUser.builder("john_lennon_jr")
      .buildEmail("john_lennon_jr@email.com")
      .active(!lennon.getActive())
      .name(name)
      .addAddress(address)
      .build();

    ScimUserPatchRequest req = getPatchAddRequest(lennon_update);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("userName", equalTo(lennon_update.getUserName()))
      .body("displayName", equalTo(lennon_update.getUserName()))
      .body("name.givenName", equalTo(name.getGivenName()))
      .body("name.familyName", equalTo(name.getFamilyName()))
      .body("name.middleName", equalTo(name.getMiddleName()))
      .body("name.formatted", equalTo(name.getFormatted()))
      .body("active", equalTo(lennon_update.getActive()))
      .body("emails", hasSize(equalTo(1)))
      .body("emails[0].value", equalTo(lennon_update.getEmails().get(0).getValue()))
      .body("addresses", hasSize(equalTo(1)))
      .body("addresses[0].formatted", equalTo(address.getFormatted()))
      .body("addresses[0].streetAddress", equalTo(address.getStreetAddress()))
      .body("addresses[0].locality", equalTo(address.getLocality()))
      .body("addresses[0].region", equalTo(address.getRegion()))
      .body("addresses[0].postalCode", equalTo(address.getPostalCode()))
      .body("addresses[0].country", equalTo(address.getCountry()));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddReassignAndRemoveOidcId() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    ScimUser lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");

    ScimIndigoUser indigoUser = ScimIndigoUser.builder()
      .addOidcid(ScimOidcId.builder().issuer("test_issuer").subject("test_subject").build())
      .build();

    ScimUser updateOidcId = ScimUser.builder().indigoUserInfo(indigoUser).build();

    ScimUserPatchRequest req = getPatchAddRequest(updateOidcId);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds[0].issuer",
          equalTo(indigoUser.getOidcIds().stream().findFirst().get().getIssuer()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds[0].subject",
          equalTo(indigoUser.getOidcIds().stream().findFirst().get().getSubject()));

    /* lincoln tryes to add the oidc account: */
    restUtils.doPatch(lincoln.getMeta().getLocation(), req, HttpStatus.CONFLICT);

    /* Remove oidc account */
    req = getPatchRemoveRequest(updateOidcId);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation()).body("id", equalTo(lennon.getId())).body(
        "urn:indigo-dc:scim:schemas:IndigoUser", equalTo(null));

    restUtils.doDelete(lennon.getMeta().getLocation());
    restUtils.doDelete(lincoln.getMeta().getLocation());
  }

  @Test
  public void testAddReassignAndRemoveSamlId() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    ScimUser lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");

    ScimIndigoUser indigoUser = ScimIndigoUser.builder()
      .addSamlId(ScimSamlId.builder().idpId("test_idp").userId("test_user").build())
      .build();

    ScimUser updateSamlId = ScimUser.builder().indigoUserInfo(indigoUser).build();

    ScimUserPatchRequest req = getPatchAddRequest(updateSamlId);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds[0].idpId",
          equalTo(indigoUser.getSamlIds().stream().findFirst().get().getIdpId()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds[0].userId",
          equalTo(indigoUser.getSamlIds().stream().findFirst().get().getUserId()));

    /* lincoln tryes to add the oidc account: */
    restUtils.doPatch(lincoln.getMeta().getLocation(), req, HttpStatus.CONFLICT);

    /* Remove oidc account */
    req = getPatchRemoveRequest(updateSamlId);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation()).body("id", equalTo(lennon.getId())).body(
        "urn:indigo-dc:scim:schemas:IndigoUser", equalTo(null));

    restUtils.doDelete(lennon.getMeta().getLocation());
    restUtils.doDelete(lincoln.getMeta().getLocation());
  }

  @Test
  public void testRemoveNotExistingOidcId() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUser lennon_update = ScimUser.builder()
      .indigoUserInfo(ScimIndigoUser.builder()
        .addOidcid(ScimOidcId.builder().issuer("test_issuer").subject("test_subject").build())
        .build())
      .build();

    ScimUserPatchRequest req = getPatchRemoveRequest(lennon_update);

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.NOT_FOUND);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddInvalidBase64X509Certificate() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUser lennon_update = ScimUser.builder()
      .buildX509Certificate("Personal Certificate", "This is not a certificate", true)
      .build();

    ScimUserPatchRequest req = getPatchAddRequest(lennon_update);

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.BAD_REQUEST);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddInvalidX509Certificate() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    String certificate = Base64.getEncoder().encodeToString("this is not a certificate".getBytes());

    ScimUser lennon_update =
        ScimUser.builder().buildX509Certificate("Personal Certificate", certificate, true).build();

    ScimUserPatchRequest req = getPatchAddRequest(lennon_update);

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.BAD_REQUEST);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddAndRemoveX509Certificate() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUser lennon_update = ScimUser.builder()
      .buildX509Certificate("Personal Certificate", TestUtils.x509Certs.get(0).certificate, true)
      .build();

    ScimUserPatchRequest req = getPatchAddRequest(lennon_update);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body("x509Certificates", hasSize(equalTo(1)))
      .body("x509Certificates[0].value", equalTo(TestUtils.x509Certs.get(0).certificate));

    ScimUser lennon_remove = ScimUser.builder()
      .buildX509Certificate(null, TestUtils.x509Certs.get(0).certificate, null)
      .build();

    req = getPatchRemoveRequest(lennon_remove);

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.NO_CONTENT);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body("x509Certificates", equalTo(null));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testPatchUserPassword() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUser patchedPasswordUser = ScimUser.builder().password("new_password").build();

    restUtils.doPatch(lennon.getMeta().getLocation(),
        ScimUserPatchRequest.builder().add(patchedPasswordUser).build());

    passwordTokenGetter().scope("openid")
      .username("john_lennon")
      .password("new_password")
      .getAccessToken();

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddReassignAndRemoveSshKey() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    ScimUser lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");

    ScimUser updateSshKey = ScimUser.builder()
      .buildSshKey("Personal", TestUtils.sshKeys.get(0).key, null, true)
      .build();

    restUtils.doPatch(lennon.getMeta().getLocation(), getPatchAddRequest(updateSshKey));

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].display", equalTo("Personal"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].value",
          equalTo(TestUtils.sshKeys.get(0).key))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].fingerprint",
          equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].primary", equalTo(true));

    /* lincoln tryes to add the lennon ssh key: */
    restUtils.doPatch(lincoln.getMeta().getLocation(), getPatchAddRequest(updateSshKey),
        HttpStatus.CONFLICT);

    restUtils.doPatch(lennon.getMeta().getLocation(), getPatchRemoveRequest(updateSshKey));

    restUtils.doDelete(lennon.getMeta().getLocation());
    restUtils.doDelete(lincoln.getMeta().getLocation());
  }

  @Test
  public void testAddSshKeyWithInvalidBase64Value() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(
        ScimUser.builder().buildSshKey("Personal", "Non Base64 String", null, true).build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.BAD_REQUEST)
      .body("status", equalTo("400"))
      .body("detail",
          equalTo("Error during fingerprint generation: RSA key is not base64 encoded"));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testRemoveSshKeyWithLabel() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder()
      .buildSshKey("Personal", TestUtils.sshKeys.get(0).key, null, true)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].display", equalTo("Personal"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].value",
          equalTo(TestUtils.sshKeys.get(0).key))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].fingerprint",
          equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256));

    req = getPatchRemoveRequest(ScimUser.builder()
      .indigoUserInfo(ScimIndigoUser.builder()
        .addSshKey(ScimSshKey.builder().display("Personal").build())
        .build())
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.NO_CONTENT);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body("urn:indigo-dc:scim:schemas:IndigoUser", equalTo(null));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testRemoveSshKeyWithFingerprint() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder()
      .buildSshKey("Personal", TestUtils.sshKeys.get(0).key, null, true)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].display", equalTo("Personal"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].value",
          equalTo(TestUtils.sshKeys.get(0).key))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].fingerprint",
          equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256));

    req =
        getPatchRemoveRequest(
            ScimUser.builder()
              .indigoUserInfo(ScimIndigoUser.builder()
                .addSshKey(ScimSshKey.builder()
                  .fingerprint(TestUtils.sshKeys.get(0).fingerprintSHA256)
                  .build())
                .build())
              .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.NO_CONTENT);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body("urn:indigo-dc:scim:schemas:IndigoUser", equalTo(null));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testRemoveSshKeyWithValue() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder()
      .buildSshKey("Personal", TestUtils.sshKeys.get(0).key, null, true)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].display", equalTo("Personal"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].value",
          equalTo(TestUtils.sshKeys.get(0).key))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].fingerprint",
          equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256));

    req = getPatchRemoveRequest(ScimUser.builder()
      .indigoUserInfo(ScimIndigoUser.builder()
        .addSshKey(ScimSshKey.builder().value(TestUtils.sshKeys.get(0).key).build())
        .build())
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req, HttpStatus.NO_CONTENT);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body("urn:indigo-dc:scim:schemas:IndigoUser", equalTo(null));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddOidcIdDuplicateInASingleRequest() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimIndigoUser indigoUser = ScimIndigoUser.builder()
      .addOidcid(ScimOidcId.builder().issuer("test_issuer").subject("test_subject").build())
      .addOidcid(ScimOidcId.builder().issuer("test_issuer").subject("test_subject").build())
      .build();

    ScimUserPatchRequest req =
        getPatchAddRequest(ScimUser.builder().indigoUserInfo(indigoUser).build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddSshKeyDuplicateInASingleRequest() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimSshKey sshKey =
        ScimSshKey.builder().display("Personal key").value(TestUtils.sshKeys.get(0).key).build();

    ScimIndigoUser indigoUser =
        ScimIndigoUser.builder().addSshKey(sshKey).addSshKey(sshKey).build();

    ScimUserPatchRequest req =
        getPatchAddRequest(ScimUser.builder().indigoUserInfo(indigoUser).build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddSamlIdDuplicateInASingleRequest() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimIndigoUser indigoUser = ScimIndigoUser.builder()
      .addSamlId(ScimSamlId.builder().idpId("Idp Test ID").userId("User Test Id").build())
      .addSamlId(ScimSamlId.builder().idpId("Idp Test ID").userId("User Test Id").build())
      .build();

    ScimUserPatchRequest req =
        getPatchAddRequest(ScimUser.builder().indigoUserInfo(indigoUser).build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddX509DuplicateInASingleRequest() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUser lennon_update = ScimUser.builder()
      .buildX509Certificate("Personal Certificate", TestUtils.x509Certs.get(0).certificate, true)
      .buildX509Certificate("Personal Certificate", TestUtils.x509Certs.get(0).certificate, true)
      .build();

    ScimUserPatchRequest req = getPatchAddRequest(lennon_update);

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testPatchAddOidIdAndSshKeyAndSamlId() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimIndigoUser indigoUser = ScimIndigoUser.builder()
      .addOidcid(ScimOidcId.builder().issuer("test_issuer").subject("test_subject").build())
      .addSshKey(ScimSshKey.builder().display("personal key").value(TestUtils.sshKeys.get(0).key).build())
      .addSamlId(ScimSamlId.builder().idpId("Idp Test ID").userId("User Test Id").build())
      .build();

    ScimUserPatchRequest req =
        getPatchAddRequest(ScimUser.builder().indigoUserInfo(indigoUser).build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds", hasSize(equalTo(1)))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds[0].issuer", equalTo("test_issuer"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".oidcIds[0].subject", equalTo("test_subject"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys", hasSize(equalTo(1)))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].display", equalTo("personal key"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].value",
          equalTo(TestUtils.sshKeys.get(0).key))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].fingerprint",
          equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].primary", equalTo(true))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds", hasSize(equalTo(1)))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds[0].idpId", equalTo("Idp Test ID"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".samlIds[0].userId", equalTo("User Test Id"));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testPatchSshKeyLabelAndPrimary() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder()
      .buildSshKey("Personal", TestUtils.sshKeys.get(0).key, null, true)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    ScimUserPatchRequest req_update = getPatchReplaceRequest(ScimUser.builder()
      .buildSshKey("New label", null, TestUtils.sshKeys.get(0).fingerprintSHA256, false)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req_update);

    /* expected primary = true because it's the only ssh key */
    restUtils.doGet(lennon.getMeta().getLocation())
      .body("id", equalTo(lennon.getId()))
      .body("userName", equalTo(lennon.getUserName()))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].display", equalTo("New label"))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].value",
          equalTo(TestUtils.sshKeys.get(0).key))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].fingerprint",
          equalTo(TestUtils.sshKeys.get(0).fingerprintSHA256))
      .body(ScimConstants.INDIGO_USER_SCHEMA + ".sshKeys[0].primary", equalTo(true));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testAddMultipleX509CertificateAndNoPrimary() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder()
      .buildX509Certificate("Personal1", TestUtils.x509Certs.get(0).certificate, false)
      .buildX509Certificate("Personal2", TestUtils.x509Certs.get(1).certificate, false)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("x509Certificates", hasSize(equalTo(2)))
      .body("x509Certificates[0].display", equalTo("Personal1"))
      .body("x509Certificates[0].value", equalTo(TestUtils.x509Certs.get(0).certificate))
      .body("x509Certificates[0].primary", equalTo(true))
      .body("x509Certificates[1].display", equalTo("Personal2"))
      .body("x509Certificates[1].value", equalTo(TestUtils.x509Certs.get(1).certificate))
      .body("x509Certificates[1].primary", equalTo(false));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testReplacePrimaryWithMultipleX509Certificate() {

    ScimUser lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder()
      .buildX509Certificate("Personal1", TestUtils.x509Certs.get(0).certificate, false)
      .buildX509Certificate("Personal2", TestUtils.x509Certs.get(1).certificate, false)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("x509Certificates", hasSize(equalTo(2)))
      .body("x509Certificates[0].display", equalTo("Personal1"))
      .body("x509Certificates[0].value", equalTo(TestUtils.x509Certs.get(0).certificate))
      .body("x509Certificates[0].primary", equalTo(true))
      .body("x509Certificates[1].display", equalTo("Personal2"))
      .body("x509Certificates[1].value", equalTo(TestUtils.x509Certs.get(1).certificate))
      .body("x509Certificates[1].primary", equalTo(false));

    req = getPatchReplaceRequest(ScimUser.builder()
      .buildX509Certificate("Personal1", TestUtils.x509Certs.get(0).certificate, false)
      .buildX509Certificate("Personal2", TestUtils.x509Certs.get(1).certificate, true)
      .build());

    restUtils.doPatch(lennon.getMeta().getLocation(), req);

    restUtils.doGet(lennon.getMeta().getLocation())
      .body("x509Certificates", hasSize(equalTo(2)))
      .body("x509Certificates[0].display", equalTo("Personal1"))
      .body("x509Certificates[0].value", equalTo(TestUtils.x509Certs.get(0).certificate))
      .body("x509Certificates[0].primary", equalTo(false))
      .body("x509Certificates[1].display", equalTo("Personal2"))
      .body("x509Certificates[1].value", equalTo(TestUtils.x509Certs.get(1).certificate))
      .body("x509Certificates[1].primary", equalTo(true));

    restUtils.doDelete(lennon.getMeta().getLocation());
  }

  @Test
  public void testEmailIsNotAlreadyLinkedOnPatch() {

    ScimUser john = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    ScimUser ringo = addTestUser("ringo_starr", "ringo@email.test", "Ringo", "Starr");

    ScimUser johnUpdated = ScimUser.builder("john_lennon").buildEmail("ringo@email.test").build();

    ScimUserPatchRequest req = getPatchAddRequest(johnUpdated);

    restUtils.doPatch(john.getMeta().getLocation(), req, HttpStatus.CONFLICT).body("detail",
        containsString("email ringo@email.test already assigned to another user"));

    restUtils.deleteUsers(john, ringo);
  }

  @Test
  public void testAddPicture() {

    final String pictureURL = "http://iosicongallery.com/img/512/angry-birds-2-2016.png";

    ScimUser user = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");

    ScimUserPatchRequest req = getPatchAddRequest(ScimUser.builder().buildPhoto(pictureURL).build());

    restUtils.doPatch(user.getMeta().getLocation(), req);

    ScimUser updatedUser = restUtils.doGet(user.getMeta().getLocation()).extract().as(ScimUser.class);

    Assert.assertTrue(!updatedUser.getPhotos().isEmpty());
    Assert.assertTrue(updatedUser.getPhotos().get(0).getValue().equals(pictureURL));

    restUtils.deleteUsers(user);
  }
}
