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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
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
@WithMockOAuthUser(user = "test_104", authorities = {"ROLE_USER"})
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
  public void testPatchRemovePicture() throws Exception {

    ScimPhoto currentPhoto = scimUtils.getMe().getPhotos().get(0);

    ScimUser updates = ScimUser.builder().addPhoto(currentPhoto).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().hasPhotos(), equalTo(false));
  }

  @Test
  public void testPatchRemoveOidcId() throws Exception {

    ScimOidcId currentOidcId = scimUtils.getMe().getIndigoUser().getOidcIds().get(0);

    ScimUser updates = ScimUser.builder().addOidcId(currentOidcId).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getIndigoUser().getOidcIds(), hasSize(equalTo(0)));
  }

  @Test
  public void testPatchRemoveSamlId() throws Exception {

    ScimSamlId currentSamlId = scimUtils.getMe().getIndigoUser().getSamlIds().get(0);

    ScimUser updates = ScimUser.builder().addSamlId(currentSamlId).build();

    scimUtils.patchMe(remove, updates);

    assertThat(scimUtils.getMe().getIndigoUser().getSamlIds(), hasSize(equalTo(0)));
  }
}
