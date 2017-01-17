package it.infn.mw.iam.test.scim.group;

import static com.jayway.restassured.matcher.ResponseAwareMatcherComposer.and;
import static com.jayway.restassured.matcher.RestAssuredMatchers.endsWithPath;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;

import java.util.UUID;

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
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimGroupProvisioningTests {

  public static final String SCIM_CONTENT_TYPE = "application/scim+json";

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

  @Test
  public void testGetGroupNotFoundResponse() {

    String randomUuid = UUID.randomUUID().toString();

    restUtils.doGet("/scim/Groups/" + randomUuid, HttpStatus.NOT_FOUND)
      .body("status", equalTo("404"))
      .body("detail", equalTo("No group mapped to id '" + randomUuid + "'"))
      .contentType(ScimRestUtils.SCIM_CONTENT_TYPE);
  }

  @Test
  public void testUpdateGroupNotFoundResponse() {

    String randomUuid = UUID.randomUUID().toString();

    ScimGroup group = ScimGroup.builder("engineers").id(randomUuid).build();

    restUtils.doPut("/scim/Groups/" + randomUuid, group, HttpStatus.NOT_FOUND)
      .body("status", equalTo("404"))
      .body("detail", equalTo("No group mapped to id '" + randomUuid + "'"))
      .contentType(ScimRestUtils.SCIM_CONTENT_TYPE);
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testGetExistingGroup() {

    // Some existing group as defined in the test db
    String groupId = "c617d586-54e6-411d-8e38-64967798fa8a";

    restUtils.doGet("/scim/Groups/" + groupId)
      .body("id", equalTo(groupId))
      .body("displayName", equalTo("Production"))
      .body("meta.resourceType", equalTo("Group"))
      .body("meta.location", equalTo("http://localhost:8080/scim/Groups/" + groupId))
      .body("members", hasSize(equalTo(1)))
      .body("members[0].$ref",
          and(startsWith("http://localhost:8080/scim/Users/"), endsWithPath("members[0].value")))
      .body("schemas", hasItems(ScimGroup.GROUP_SCHEMA, ScimConstants.INDIGO_GROUP_SCHEMA));

  }

  @Test
  public void testCreateAndDeleteGroupSuccessResponse() {

    String name = "engineers";

    ScimGroup group = ScimGroup.builder(name).build();

    ScimGroup createdGroup = restUtils.doPost("/scim/Groups/", group).extract().as(ScimGroup.class);

    restUtils.doGet(createdGroup.getMeta().getLocation())
      .body("displayName", equalTo(name));

    restUtils.doDelete(createdGroup.getMeta().getLocation(), HttpStatus.NO_CONTENT);
  }

  @Test
  public void testUpdateGroupDisplaynameSuccessResponse() {

    ScimGroup requestedGroup = ScimGroup.builder("engineers").build();

    ScimGroup createdGroup =
        restUtils.doPost("/scim/Groups/", requestedGroup).extract().as(ScimGroup.class);

    requestedGroup = ScimGroup.builder("engineers_updated").build();

    restUtils.doPut(createdGroup.getMeta().getLocation(), requestedGroup)
      .body("displayName", equalTo(requestedGroup.getDisplayName()));

    restUtils.doDelete(createdGroup.getMeta().getLocation(), HttpStatus.NO_CONTENT);
  }

  @Test
  public void testCreateGroupEmptyDisplayNameValidationError() {

    String displayName = "";

    ScimGroup group = ScimGroup.builder(displayName).build();

    restUtils.doPost("/scim/Groups/", group, HttpStatus.BAD_REQUEST).body("detail",
        containsString("scimGroup.displayName : may not be empty"));

  }

  @Test
  public void testUpdateGroupEmptyDisplayNameValidationErro() {

    ScimGroup requestedGroup = ScimGroup.builder("engineers").build();

    ScimGroup createdGroup =
        restUtils.doPost("/scim/Groups/", requestedGroup).extract().as(ScimGroup.class);

    requestedGroup = ScimGroup.builder("").build();

    restUtils.doPut(createdGroup.getMeta().getLocation(), requestedGroup, HttpStatus.BAD_REQUEST);

    restUtils.doDelete(createdGroup.getMeta().getLocation(), HttpStatus.NO_CONTENT);
  }

  @Test
  public void testUpdateGroupAlreadyUsedDisplaynameError() {

    ScimGroup engineers =
        restUtils.doPost("/scim/Groups/", ScimGroup.builder("engineers").build())
          .extract()
          .as(ScimGroup.class);

    ScimGroup artists =
        restUtils.doPost("/scim/Groups/", ScimGroup.builder("artists").build())
          .extract()
          .as(ScimGroup.class);

    restUtils.doPut(engineers.getMeta().getLocation(),
        ScimGroup.builder("artists").build(), HttpStatus.CONFLICT);

    restUtils.doDelete(engineers.getMeta().getLocation(), HttpStatus.NO_CONTENT);
    restUtils.doDelete(artists.getMeta().getLocation(), HttpStatus.NO_CONTENT);
  }

}
