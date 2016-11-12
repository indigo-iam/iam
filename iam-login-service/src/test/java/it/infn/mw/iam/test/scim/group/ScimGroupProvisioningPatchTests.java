package it.infn.mw.iam.test.scim.group;

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
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.ScimRestUtils;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ScimGroupProvisioningPatchTests {

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

  private ScimGroupPatchRequest getPatchAddUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().add(TestUtils.buildScimMemberRefList(users)).build();
  }

  private ScimGroupPatchRequest getPatchRemoveUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().remove(TestUtils.buildScimMemberRefList(users)).build();
  }

  private ScimGroupPatchRequest getPatchRemoveAllUsersRequest() {

    return ScimGroupPatchRequest.builder().remove(null).build();
  }

  private ScimGroupPatchRequest getPatchReplaceUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().replace(TestUtils.buildScimMemberRefList(users)).build();
  }

  @Test
  public void testAddMemberToGroup() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);

    ScimGroupPatchRequest patchReq = getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(1)))
      .body("members[0].display", equalTo(lennon.getDisplayName()))
      .body("members[0].value", equalTo(lennon.getId()))
      .body("members[0].$ref", equalTo(lennon.getMeta().getLocation()));

  }

  @Test
  public void testRemoveNonMemberFromGroup() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);

    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);
  }

  @Test
  public void testAddAndRemoveMultipleMembersToGroup() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);
    members.add(lincoln);

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchAddReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(2)));

    ScimGroupPatchRequest patchRemoveReq = getPatchRemoveUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchRemoveReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", equalTo(null));
  }

  @Test
  public void testAddMultipleMembersToGroup() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    ScimUser fakeUser = addTestUser("fake_user", "mail@domain.com", "Fake", "User");
    members.add(lennon);
    members.add(fakeUser);
    restUtils.doDelete(fakeUser.getMeta().getLocation());

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchAddReq, HttpStatus.NOT_FOUND);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", equalTo(null));
  }

  @Test
  public void testRemoveMultipleMembersToGroup() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);
    members.add(lincoln);

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchAddReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(2)));

    ScimGroupPatchRequest patchRemoveReq = getPatchRemoveAllUsersRequest();

    restUtils.doPatch(engineers.getMeta().getLocation(), patchRemoveReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", equalTo(null));
  }

  @Test
  public void testReplaceMember() {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);

    List<ScimUser> replacedMembers = new ArrayList<ScimUser>();
    replacedMembers.add(lincoln);

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchAddReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(1)))
      .body("members[0].display", equalTo(lennon.getUserName()));

    ScimGroupPatchRequest patchReplaceReq = getPatchReplaceUsersRequest(replacedMembers);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReplaceReq);

    restUtils.doGet(engineers.getMeta().getLocation())
      .body("id", equalTo(engineers.getId()))
      .body("displayName", equalTo(engineers.getDisplayName()))
      .body("members", hasSize(equalTo(1)))
      .body("members[0].display", equalTo(lincoln.getUserName()));
  }

}
