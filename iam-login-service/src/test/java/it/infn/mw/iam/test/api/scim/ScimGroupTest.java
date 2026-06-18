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

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

class ScimGroupTest extends ScimMockMvcTestSupport {

  @Test
  void fullGroupLifecycle() throws Exception {

    String token =
        clientCredentialsToken(StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_ID,
            StructuredScopeTestSupportConstants.SCIM_CLIENT_RW_SECRET, "scim:read scim:write");

    ScimGroup group = ScimGroup.builder("scim-test-group").build();

    String groupJson = mapper.writeValueAsString(group);

    var create = authorizedPost(SCIM_BASE + "/Groups", token, groupJson);
    assertEquals(201, create.getResponse().getStatus());

    JsonNode groupResponse = mapper.readTree(create.getResponse().getContentAsString());
    String groupId = groupResponse.get("id").asText();

    // Delete group
    assertEquals(204,
        authorizedDelete(SCIM_BASE + "/Groups/" + groupId, token).getResponse().getStatus());
  }

}
