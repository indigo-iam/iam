package it.infn.mw.iam.test.scim.group.patch;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
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

import com.google.common.collect.Lists;

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
public class ScimGroupProvisioningPatchRemoveTests {

  public static final String SCIM_CONTENT_TYPE = "application/scim+json";

  private String accessToken;
  private ScimRestUtils restUtils;

  private ScimGroup engineers;
  private ScimUser lennon;
  private ScimUser lincoln;
  private ScimUser kennedy;

  List<ScimUser> members;

  @BeforeClass
  public static void init() {

    JacksonUtils.initRestAssured();
  }

  @Before
  public void initTests() {

    accessToken = TestUtils.getAccessToken("scim-client-rw", "secret", "scim:read scim:write");
    restUtils = ScimRestUtils.getInstance(accessToken);

    engineers = addTestGroup("engineers");
    lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
    kennedy = addTestUser("jfk", "jfk@whitehouse.us", "John", "Kennedy");

    members = new ArrayList<ScimUser>();
    members.add(lennon);
    members.add(lincoln);
    members.add(kennedy);

    addMembers(engineers, members);
  }

  @After
  public void teardownTests() {

    restUtils.doDelete(lennon.getMeta().getLocation());
    restUtils.doDelete(lincoln.getMeta().getLocation());
    restUtils.doDelete(kennedy.getMeta().getLocation());
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

  private void addMembers(ScimGroup group, List<ScimUser> members) {

    ScimGroupPatchRequest patchAddReq = ScimGroupPatchUtils.getPatchAddUsersRequest(members);

    restUtils.doPatch(group.getMeta().getLocation(), patchAddReq);

    ScimGroup g = getGroup(group.getMeta().getLocation());

    Assert.assertTrue(g.getMembers().contains(TestUtils.getMemberRef(members.get(0))));
    Assert.assertTrue(g.getMembers().contains(TestUtils.getMemberRef(members.get(1))));
    Assert.assertTrue(g.getMembers().contains(TestUtils.getMemberRef(members.get(2))));
  }

  private void assertMembership(ScimUser user, ScimGroup group, boolean isMember) {

    assertThat(group.getMembers().stream().anyMatch(m -> m.getValue().equals(user.getId())),
        equalTo(isMember));
  }

  private ScimGroup getGroup(String location) {
    return restUtils.doGet(location).extract().as(ScimGroup.class);
  }

  @Test
  public void testGroupPatchRemoveMember() {

    ScimGroupPatchRequest patchRemoveRequest =
        ScimGroupPatchUtils.getPatchRemoveUsersRequest(Lists.newArrayList(lennon));

    ScimGroup engineersBeforeUpdate = getGroup(engineers.getMeta().getLocation());

    assertThat(engineersBeforeUpdate.getMembers().size(), equalTo(3));
    assertMembership(lennon, engineersBeforeUpdate, true);
    assertMembership(lincoln, engineersBeforeUpdate, true);
    assertMembership(kennedy, engineersBeforeUpdate, true);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchRemoveRequest);

    ScimGroup engineersAfterUpdate = getGroup(engineers.getMeta().getLocation());

    assertThat(engineersAfterUpdate.getMembers().size(), equalTo(2));
    assertMembership(lennon, engineersAfterUpdate, false);
    assertMembership(lincoln, engineersAfterUpdate, true);
    assertMembership(kennedy, engineersAfterUpdate, true);

    assertThat(engineersBeforeUpdate.getMeta().getLastModified(),
        not(equalTo(engineersAfterUpdate.getMeta().getLastModified())));
  }

  @Test
  public void testGroupPatchRemoveMultipleMembers() {

    List<ScimUser> membersToRemove = new ArrayList<ScimUser>();
    membersToRemove.add(lennon);
    membersToRemove.add(lincoln);

    ScimGroupPatchRequest patchReq =
        ScimGroupPatchUtils.getPatchRemoveUsersRequest(membersToRemove);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());

    assertMembership(kennedy, updatedGroup, true);
    assertMembership(lennon, updatedGroup, false);
    assertMembership(lincoln, updatedGroup, false);
  }

  @Test
  public void testGroupPatchRemoveAllListOfMembers() {

    List<ScimUser> membersToRemove = new ArrayList<ScimUser>();
    membersToRemove.add(lennon);
    membersToRemove.add(lincoln);
    membersToRemove.add(kennedy);

    ScimGroupPatchRequest patchReq =
        ScimGroupPatchUtils.getPatchRemoveUsersRequest(membersToRemove);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());

    assertThat(updatedGroup.getMembers().isEmpty(), equalTo(true));
  }

  @Test
  public void testGroupPatchRemoveAllMembers() {

    List<ScimUser> emptyMembers = new ArrayList<ScimUser>();

    ScimGroupPatchRequest patchReq = ScimGroupPatchUtils.getPatchRemoveUsersRequest(emptyMembers);

    restUtils.doPatch(engineers.getMeta().getLocation(), patchReq);

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());

    Assert.assertTrue(updatedGroup.getMembers().isEmpty());
  }

  @Test
  public void testGroupPatchRemoveMemberTwice() {

    ScimGroupPatchRequest patchRemoveRequest =
        ScimGroupPatchUtils.getPatchRemoveUsersRequest(Lists.newArrayList(lennon));

    restUtils.doPatch(engineers.getMeta().getLocation(), patchRemoveRequest);

    ScimGroup engineersBeforeUpdate = getGroup(engineers.getMeta().getLocation());

    restUtils.doPatch(engineers.getMeta().getLocation(), patchRemoveRequest);

    ScimGroup engineersAfterUpdate = getGroup(engineers.getMeta().getLocation());

    assertMembership(lennon, engineersAfterUpdate, false);

    assertThat(engineersBeforeUpdate.getMeta().getLastModified(),
        equalTo(engineersAfterUpdate.getMeta().getLastModified()));
  }

}
