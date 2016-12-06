package it.infn.mw.iam.test.scim.group.patch;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

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
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimGroupProvisioningPatchReplaceTests {

  public static final String SCIM_CONTENT_TYPE = "application/scim+json";

  private String accessToken;
  private ScimRestUtils restUtils;

  private ScimGroup engineers;
  private ScimUser lennon;
  private ScimUser lincoln;

  @BeforeClass
  public static void init() {

    JacksonUtils.initRestAssured();
  }

  @Before
  public void initAccessToken() {

    accessToken = TestUtils.getAccessToken("scim-client-rw", "secret", "scim:read scim:write");
    restUtils = ScimRestUtils.getInstance(accessToken);

    engineers = addTestGroup("engineers");
    lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
  }

  @After
  public void teardownTests() {

    restUtils.doDelete(lennon.getMeta().getLocation());
    restUtils.doDelete(lincoln.getMeta().getLocation());
    restUtils.doDelete(engineers.getMeta().getLocation());
  }

  private ScimGroup addTestGroup(String displayName) {

    ScimGroup group = ScimGroup.builder(displayName).build();

    return restUtils.doPost("/scim/Groups/", group).extract().as(ScimGroup.class);
  }

  private ScimUser addTestUser(String userName, String email, String firstName, String LastName) {

    ScimUser lennon =
        ScimUser.builder(userName).buildEmail(email).buildName(firstName, LastName).build();

    return restUtils.doPost("/scim/Users/", lennon).extract().as(ScimUser.class);
  }

  @Test
  public void testGroupPatchReplaceMember() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);

    ScimGroupPatchRequest patchReq = ScimGroupPatchUtils.getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(1)))
      .body("members[0].display", equalTo(lennon.getDisplayName()))
      .body("members[0].value", equalTo(lennon.getId()))
      .body("members[0].$ref", equalTo(lennon.getMeta().getLocation()));

    members.remove(lennon);
    members.add(lincoln);
    patchReq = ScimGroupPatchUtils.getPatchReplaceUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    ScimGroup updatedGroup =
        restUtils.doGet(engineers.getMeta().getLocation()).extract().as(ScimGroup.class);

    Assert.assertTrue(updatedGroup.getMembers().size() == 1);
    Assert.assertTrue(updatedGroup.getMembers().contains(TestUtils.getMemberRef(lincoln)));
  }

  @Test
  public void testGroupPatchReplaceSameMember() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);

    ScimGroupPatchRequest patchReq = ScimGroupPatchUtils.getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(1)))
      .body("members[0].display", equalTo(lennon.getDisplayName()))
      .body("members[0].value", equalTo(lennon.getId()))
      .body("members[0].$ref", equalTo(lennon.getMeta().getLocation()));

    patchReq = ScimGroupPatchUtils.getPatchReplaceUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    ScimGroup updatedGroup =
        restUtils.doGet(engineers.getMeta().getLocation()).extract().as(ScimGroup.class);

    Assert.assertTrue(updatedGroup.getMembers().size() == 1);
    Assert.assertTrue(updatedGroup.getMembers().contains(TestUtils.getMemberRef(lennon)));
  }

  @Test
  public void testGroupPatchReplaceWithEmptyMemberList() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    ScimGroupPatchRequest patchReq = ScimGroupPatchUtils.getPatchReplaceUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);
    
    ScimGroup updatedGroup =
        restUtils.doGet(engineers.getMeta().getLocation()).extract().as(ScimGroup.class);
    assertThat(updatedGroup.getMembers().isEmpty(), equalTo(true));
    
  }
}
