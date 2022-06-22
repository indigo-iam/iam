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

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
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
@WithMockOAuthUser(user = "test_105", authorities = {"ROLE_USER"})
public class ScimMeEndpointPatchReplaceTests extends ScimMeEndpointUtils {

  @Autowired
  private ScimRestUtilsMvc scimUtils;
  @Autowired
  private ScimUserProvisioning provider;

  @Before
  public void init() throws Exception {

    String uuid = scimUtils.getMe().getId();

    ScimUser updates = ScimUser.builder()
      .buildPhoto("http://site.org/user.png")
      .addOidcId(TESTUSER_OIDCID)
      .addSamlId(TESTUSER_SAMLID)
      .addX509Certificate(TESTUSER_X509CERT)
      .addSshKey(TESTUSER_SSHKEY)
      .build();

    List<ScimPatchOperation<ScimUser>> operations = Lists.newArrayList();
    operations.add(new ScimPatchOperation.Builder<ScimUser>().add().value(updates).build());
    provider.update(uuid, operations);
  }

  @Test
  public void testPatchReplacePasswordNotSupported() throws Exception {

    final String NEW_PASSWORD = "newpassword";

    ScimUser updates = ScimUser.builder().password(NEW_PASSWORD).build();

    scimUtils.patchMe(replace, updates, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testPatchReplaceGivenAndFamilyName() throws Exception {

    ScimUser updates = ScimUser.builder().name(TESTUSER_NEWNAME).build();

    scimUtils.patchMe(replace, updates);

    ScimUser userAfter = scimUtils.getMe();

    assertThat(userAfter.getName().getGivenName(), equalTo(updates.getName().getGivenName()));
    assertThat(userAfter.getName().getFamilyName(), equalTo(updates.getName().getFamilyName()));
  }

  @Test

  public void testPatchReplacePicture() throws Exception {

    ScimUser updates = ScimUser.builder().addPhoto(TESTUSER_NEWPHOTO).build();

    scimUtils.patchMe(replace, updates);

    ScimPhoto updatedPhoto = scimUtils.getMe().getPhotos().get(0);

    assertThat(updatedPhoto, equalTo(TESTUSER_NEWPHOTO));
  }

  @Test

  public void testPatchReplaceEmail() throws Exception {

    ScimUser updates = ScimUser.builder().addEmail(TESTUSER_NEWEMAIL).build();

    scimUtils.patchMe(replace, updates);

    ScimUser updatedUser = scimUtils.getMe();

    assertThat(updatedUser.getEmails().get(0), equalTo(TESTUSER_NEWEMAIL));
  }

  @Test
  public void testPatchReplaceAlreadyUsedEmail() throws Exception {

    ScimUser updates = ScimUser.builder().addEmail(ANOTHERUSER_EMAIL).build();

    scimUtils.patchMe(replace, updates, HttpStatus.CONFLICT)
      .andExpect(jsonPath("$.detail", containsString("already bound to another user")));
  }

  @Test
  public void testPatchReplaceOidcIdNotSupported() throws Exception {

    ScimUser updates = ScimUser.builder().addOidcId(TESTUSER_OIDCID).build();

    scimUtils.patchMe(replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("replace operation not supported")));
  }

  @Test
  public void testPatchReplaceSamlIdNotSupported() throws Exception {

    ScimUser updates = ScimUser.builder().addSamlId(TESTUSER_SAMLID).build();

    scimUtils.patchMe(replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("replace operation not supported")));
  }

  @Test
  public void testPatchReplaceX509CertificateNotSupported() throws Exception {

    ScimUser updates = ScimUser.builder().addX509Certificate(TESTUSER_X509CERT).build();

    scimUtils.patchMe(replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("replace operation not supported")));
  }

  @Test
  public void testPatchReplaceSshKeyNotSupported() throws Exception {

    ScimUser updates = ScimUser.builder().addSshKey(TESTUSER_SSHKEY).build();

    scimUtils.patchMe(replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("replace operation not supported")));
  }
}
