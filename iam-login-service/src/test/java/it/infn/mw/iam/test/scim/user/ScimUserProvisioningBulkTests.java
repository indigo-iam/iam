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
package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.addPatchOperationToBulk;
import static it.infn.mw.iam.test.scim.ScimUtils.addPostOperationToBulk;
import static it.infn.mw.iam.test.scim.ScimUtils.buildUser;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUsersBulkRequest;
import it.infn.mw.iam.api.scim.model.ScimUsersBulkResponse;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"scim.include_authorities=true"})
public class ScimUserProvisioningBulkTests extends ScimUserTestSupport {

  private String ADMINID = "73f16d93-2441-4a50-88ff-85360d78c6b5";

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private ObjectMapper objectMapper;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testPostSuccessPatchSuccess() throws Exception {

    JsonNode user = objectMapper.valueToTree(buildUser("paul_mccartney", "test@email.test", "Paul", "McCartney").build());
    ScimUsersBulkRequest.Builder bulkRequest = addPostOperationToBulk(ScimUsersBulkRequest.requestBuilder(), user, "paul_mccartney");
    ScimUser updates = ScimUser.builder().buildEmail("ringo@star.com").build();
    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(updates).build();
    ScimUsersBulkRequest finalRequest = addPatchOperationToBulk(bulkRequest, objectMapper.valueToTree(patchRequest), ADMINID).build();
    ScimUsersBulkResponse response = scimUtils.postUserBulk(finalRequest);

    assertThat(response.getOperations(), hasSize(equalTo(2)));
    assertEquals(response.getOperations().get(0).getStatus(), "201");
    assertEquals(response.getOperations().get(1).getStatus(), "200");
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testPostSuccessPatchFail() throws Exception {

    JsonNode user = objectMapper.valueToTree(buildUser("paul_mccartney", "test@email.test", "Paul", "McCartney").build());
    ScimUsersBulkRequest.Builder bulkRequest = addPostOperationToBulk(ScimUsersBulkRequest.requestBuilder(), user, "paul_mccartney");
    ScimUser updates = ScimUser.builder().buildEmail("ringo@star.com").build();
    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(updates).build();
    ScimUsersBulkRequest finalRequest = addPatchOperationToBulk(bulkRequest, objectMapper.valueToTree(patchRequest), "fake").build();
    ScimUsersBulkResponse response = scimUtils.postUserBulk(finalRequest);

    assertThat(response.getOperations(), hasSize(equalTo(2)));
    assertEquals("201",response.getOperations().get(0).getStatus());
    assertEquals("404", response.getOperations().get(1).getStatus());
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testPostFailPatchSuccess() throws Exception {

    ScimUser user = buildUser("paul_mccartney", "test@email.test", "Paul", "McCartney").build();
    ScimUsersBulkRequest.Builder postUser = addPostOperationToBulk(ScimUsersBulkRequest.requestBuilder(), objectMapper.valueToTree(user), "paul_mccartney");
    ScimUsersBulkRequest.Builder duplicatePost = addPostOperationToBulk(postUser, objectMapper.valueToTree(user), "paul_mccartney");
    ScimUser updates = ScimUser.builder().buildEmail("ringo@star.com").build();
    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(updates).build();
    ScimUsersBulkRequest finalRequest = addPatchOperationToBulk(duplicatePost, objectMapper.valueToTree(patchRequest), ADMINID).build();
    ScimUsersBulkResponse response = scimUtils.postUserBulk(finalRequest);

    assertThat(response.getOperations(), hasSize(equalTo(3)));
    assertEquals("201", response.getOperations().get(0).getStatus());
    assertEquals("409", response.getOperations().get(1).getStatus());
    assertEquals("200", response.getOperations().get(2).getStatus());
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testPostFailPatchFail() throws Exception {
    JsonNode user = objectMapper.valueToTree(buildUser("admin", "test@email.test", "Paul", "McCartney").build());
    ScimUsersBulkRequest.Builder bulkRequest = addPostOperationToBulk(ScimUsersBulkRequest.requestBuilder(), user, "paul_mccartney");
    ScimUser updates = ScimUser.builder().buildEmail("ringo@star.com").build();
    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(updates).build();
    ScimUsersBulkRequest finalRequest = addPatchOperationToBulk(bulkRequest, objectMapper.valueToTree(patchRequest), "fake").build();
    ScimUsersBulkResponse response = scimUtils.postUserBulk(finalRequest);

    assertThat(response.getOperations(), hasSize(equalTo(2)));
    assertEquals("409", response.getOperations().get(0).getStatus());
    assertEquals("404", response.getOperations().get(1).getStatus());
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testFailOnErrors() throws Exception {
    JsonNode user = objectMapper.valueToTree(buildUser("admin", "test@email.test", "Paul", "McCartney").build());
    ScimUsersBulkRequest.Builder bulkRequest = addPostOperationToBulk(ScimUsersBulkRequest.requestBuilder(1), user, "paul_mccartney");
    ScimUser updates = ScimUser.builder().buildEmail("ringo@star.com").build();
    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().replace(updates).build();
    ScimUsersBulkRequest finalRequest = addPatchOperationToBulk(bulkRequest, objectMapper.valueToTree(patchRequest), "fake").build();
    ScimUsersBulkResponse response = scimUtils.postUserBulk(finalRequest);

    assertThat(finalRequest.getOperations(), hasSize(equalTo(2)));
    assertThat(response.getOperations(), hasSize(equalTo(1)));
    assertEquals("409", response.getOperations().get(0).getStatus());
  }

}

