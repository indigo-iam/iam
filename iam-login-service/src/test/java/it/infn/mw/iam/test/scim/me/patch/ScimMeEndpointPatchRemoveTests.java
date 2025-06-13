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
package it.infn.mw.iam.test.scim.me.patch;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
public class ScimMeEndpointPatchRemoveTests {

  @Autowired
  private ScimRestUtilsMvc scimUtils;
  @Autowired
  private ScimUserProvisioning provider;

  @Before
  public void init() throws Exception {

    String uuid = scimUtils.getMe().getId();

    ScimUser updates = ScimUser.builder()
      .buildPhoto("http://site.org/user.png")
      .buildOidcId("ISS", "SUB")
      .buildSamlId("IDP", "UID")
      .build();

    List<ScimPatchOperation<ScimUser>> operations = Lists.newArrayList();

    operations.add(new ScimPatchOperation.Builder<ScimUser>().add().value(updates).build());

    provider.update(uuid, operations);
  }

  @Test
  @WithMockOAuthUser(user = "test_104", authorities = {"ROLE_USER"},
      scopes = {"scim:write", "scim:read"})
  public void testPatchRemovePicture() throws Exception {

    ScimPhoto currentPhoto = scimUtils.getMe().getPhotos().get(0);

    ScimUser updates = ScimUser.builder().addPhoto(currentPhoto).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().hasPhotos(), equalTo(false));
  }

  @Test
  @WithMockOAuthUser(user = "test_104", authorities = {"ROLE_USER"},
      scopes = {"scim:write", "scim:read"})
  public void testPatchRemoveOidcId() throws Exception {

    ScimOidcId currentOidcId = scimUtils.getMe().getIndigoUser().getOidcIds().get(0);

    ScimUser updates = ScimUser.builder().addOidcId(currentOidcId).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getIndigoUser().getOidcIds(), hasSize(equalTo(0)));
  }

  @Test
  @WithMockOAuthUser(user = "test_104", authorities = {"ROLE_USER"},
      scopes = {"scim:write", "scim:read"})
  public void testPatchRemoveSamlId() throws Exception {

    ScimSamlId currentSamlId = scimUtils.getMe().getIndigoUser().getSamlIds().get(0);

    ScimUser updates = ScimUser.builder().addSamlId(currentSamlId).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getIndigoUser().getSamlIds(), hasSize(equalTo(0)));
  }

  @Test
  @WithMockOAuthUser(user = "test_104", authorities = {"ROLE_USER"},
      scopes = {"scim:write", "scim:read"})
  public void testPatchRemoveGroup() throws Exception {

    assertThat(scimUtils.getMe().getGroups(), hasSize(equalTo(2)));
    assertThat(scimUtils.getMe().getGroups()).extracting(ScimGroupRef::getDisplay)
      .contains("Analysis");
    assertThat(scimUtils.getMe().getGroups()).extracting(ScimGroupRef::getDisplay)
      .contains("Production");

    ScimGroupRef group = scimUtils.getMe().getGroups().iterator().next();

    assertEquals("Analysis", group.getDisplay());

    ScimUser updates = ScimUser.builder().addGroupRef(group).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getGroups(), hasSize(equalTo(1)));
  }

  @Test
  @WithMockOAuthUser(user = "test_104", authorities = {"ROLE_USER"},
      scopes = {"scim:write", "scim:read"})
  public void testPatchRemoveGroups() throws Exception {

    Set<ScimGroupRef> groups = scimUtils.getMe().getGroups();

    assertThat(groups, hasSize(equalTo(2)));

    ScimUser.Builder builder = ScimUser.builder();

    for (ScimGroupRef group : groups) {
      builder.addGroupRef(group);
    }

    ScimUser updates = builder.build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().hasGroups(), equalTo(false));
  }

  @Test
  @WithMockUser(username = "test_104", roles = {"USER"})
  public void testPatchRemovePictureNoToken() throws Exception {

    ScimPhoto currentPhoto = scimUtils.getMe().getPhotos().get(0);

    ScimUser updates = ScimUser.builder().addPhoto(currentPhoto).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().hasPhotos(), equalTo(false));
  }

  @Test
  @WithMockUser(username = "test_104", roles = {"USER"})
  public void testPatchRemoveOidcIdNoToken() throws Exception {

    ScimOidcId currentOidcId = scimUtils.getMe().getIndigoUser().getOidcIds().get(0);

    ScimUser updates = ScimUser.builder().addOidcId(currentOidcId).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getIndigoUser().getOidcIds(), hasSize(equalTo(0)));
  }

  @Test
  @WithMockUser(username = "test_104", roles = {"USER"})
  public void testPatchRemoveSamlIdNoToken() throws Exception {

    ScimSamlId currentSamlId = scimUtils.getMe().getIndigoUser().getSamlIds().get(0);

    ScimUser updates = ScimUser.builder().addSamlId(currentSamlId).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getIndigoUser().getSamlIds(), hasSize(equalTo(0)));
  }

  @Test
  @WithMockUser(username = "test_104", roles = {"USER"})
  public void testPatchRemoveGroupNoToken() throws Exception {

    ScimGroupRef group = scimUtils.getMe().getGroups().iterator().next();

    ScimUser updates = ScimUser.builder().addGroupRef(group).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getGroups(), hasSize(equalTo(1)));
  }
}
