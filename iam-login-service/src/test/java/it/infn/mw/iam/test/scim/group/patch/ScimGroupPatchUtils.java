package it.infn.mw.iam.test.scim.group.patch;

import java.util.List;

import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.TestUtils;

public class ScimGroupPatchUtils {

  public static ScimGroupPatchRequest getPatchAddUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().add(TestUtils.buildScimMemberRefList(users)).build();
  }

  public static ScimGroupPatchRequest getPatchRemoveUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().remove(TestUtils.buildScimMemberRefList(users)).build();
  }

  public static ScimGroupPatchRequest getPatchReplaceUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().replace(TestUtils.buildScimMemberRefList(users)).build();
  }
}
