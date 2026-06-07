/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.api.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

class ScimMembershipTest extends ScimMockMvcTestSupport {

  @Test
  void addUserToGroup() throws Exception {

    String token = passwordToken(StructuredScopeTestSupportConstants.ADMIN_USERNAME,
        StructuredScopeTestSupportConstants.ADMIN_PASSWORD,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_ID,
        StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_SECRET, "scim:read scim:write");

    ScimUser memberUser = ScimUser.builder()
      .userName("scim-member-user")
      .name(ScimName.builder().givenName("Member").familyName("User").build())
      .addEmail(ScimEmail.builder().email("member@test.org").build())
      .build();

    var user = authorizedPost(SCIM_BASE + "/Users", token, mapper.writeValueAsString(memberUser));

    String userId = mapper.readTree(user.getResponse().getContentAsString()).get("id").asText();

    ScimGroup memberGroup = ScimGroup.builder("member-group").build();

    var group =
        authorizedPost(SCIM_BASE + "/Groups", token, mapper.writeValueAsString(memberGroup));

    String groupId = mapper.readTree(group.getResponse().getContentAsString()).get("id").asText();

    ScimGroupPatchRequest groupRequest = ScimGroupPatchRequest.builder()
      .add(List.of(ScimMemberRef.builder().value(userId).build()))
      .build();

    assertEquals(204, authorizedPatch(SCIM_BASE + "/Groups/" + groupId, token,
        mapper.writeValueAsString(groupRequest)).getResponse().getStatus());
  }

}
