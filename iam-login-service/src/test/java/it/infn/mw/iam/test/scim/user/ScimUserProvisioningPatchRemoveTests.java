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

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimUser;
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
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
public class ScimUserProvisioningPatchRemoveTests extends ScimUserTestSupport {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }


  @Test
  public void testPatchRemoveOidcId() throws Exception {

    ScimUser user = createLennonTestUser();

    ScimUser updates =
        ScimUser.builder().addOidcId(user.getIndigoUser().getOidcIds().get(0)).build();

    scimUtils.patchUser(user.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user.getId());

    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(0)));
  }

  @Test
  public void testPatchRemoveAnotherUserOidcId() throws Exception {


    ScimUser user1 = createLennonTestUser();
    ScimUser user2 = createLincolnTestUser();

    ScimUser updates =
        ScimUser.builder().addOidcId(user2.getIndigoUser().getOidcIds().get(0)).build();

    scimUtils.patchUser(user1.getId(), remove, updates);

    ScimUser updatedUser1 = scimUtils.getUser(user1.getId());
    assertThat(updatedUser1.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));

    ScimUser updatedUser2 = scimUtils.getUser(user2.getId());
    assertThat(updatedUser2.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
  }

  @Test
  public void testPatchRemoveNotFoundOidcId() throws Exception {

    ScimUser user = createLennonTestUser();

    ScimUser updates = ScimUser.builder()
      .addOidcId(ScimOidcId.builder().issuer("fake_issuer").subject("fake_subject").build())
      .build();

    scimUtils.patchUser(user.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user.getId());
    assertThat(updatedUser.getId(), equalTo(user.getId()));
    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
  }

  @Test
  public void testPatchRemoveX509Certificate() throws Exception {

    ScimUser user = createLennonTestUser();

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(user.getIndigoUser().getCertificates().get(0))
      .build();

    scimUtils.patchUser(user.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user.getId());
    assertThat(updatedUser.getId(), equalTo(user.getId()));
    assertThat(updatedUser.getIndigoUser().getCertificates(), empty());
  }

  @Test
  public void testPatchRemoveAnotherUserX509Certificate() throws Exception {

    ScimUser user1 = createLennonTestUser();
    ScimUser user2 = createLincolnTestUser();

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(user2.getIndigoUser().getCertificates().get(0))
      .build();

    scimUtils.patchUser(user1.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user1.getId());
    assertThat(updatedUser.getId(), equalTo(user1.getId()));
    assertThat(updatedUser.getIndigoUser().getCertificates(), hasSize(equalTo(1)));
  }

  @Test
  public void testPatchRemoveNotFoundX509Certificate() throws Exception {

    ScimUser user1 = createLennonTestUser();

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(user1.getIndigoUser().getCertificates().get(0))
      .build();

    scimUtils.patchUser(user1.getId(), remove, updates);
    scimUtils.patchUser(user1.getId(), remove, updates);
  }

  @Test
  public void testPatchRemoveSshKey() throws Exception {

    ScimUser user = createLennonTestUser();

    ScimUser updates =
        ScimUser.builder().addSshKey(user.getIndigoUser().getSshKeys().get(0)).build();

    scimUtils.patchUser(user.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user.getId());
    assertThat(updatedUser.getId(), equalTo(user.getId()));
    assertThat(updatedUser.getIndigoUser().getSshKeys(), hasSize(equalTo(0)));
  }

  @Test
  public void testPatchRemoveAnotherUserSshKey() throws Exception {

    ScimUser user1 = createLennonTestUser();
    ScimUser user2 = createLincolnTestUser();

    ScimUser updates =
        ScimUser.builder().addSshKey(user2.getIndigoUser().getSshKeys().get(0)).build();

    scimUtils.patchUser(user1.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user1.getId());
    assertThat(updatedUser.getId(), equalTo(user1.getId()));
    assertThat(updatedUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
  }

  @Test
  public void testPatchRemoveNotFoundSshKey() throws Exception {

    ScimUser user1 = createLennonTestUser();

    ScimUser updates =
        ScimUser.builder().addSshKey(user1.getIndigoUser().getSshKeys().get(0)).build();

    scimUtils.patchUser(user1.getId(), remove, updates);
    scimUtils.patchUser(user1.getId(), remove, updates);
  }

  @Test
  public void testPatchRemoveSamlId() throws Exception {

    ScimUser user = createLennonTestUser();

    ScimUser updates =
        ScimUser.builder().addSamlId(user.getIndigoUser().getSamlIds().get(0)).build();

    scimUtils.patchUser(user.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user.getId());
    assertThat(updatedUser.getId(), equalTo(user.getId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(0)));
  }

  @Test
  public void testPatchRemoveAnotherUserSamlId() throws Exception {

    ScimUser user1 = createLennonTestUser();
    ScimUser user2 = createLincolnTestUser();

    ScimUser updates =
        ScimUser.builder().addSamlId(user2.getIndigoUser().getSamlIds().get(0)).build();

    scimUtils.patchUser(user1.getId(), remove, updates);

    ScimUser updatedUser1 = scimUtils.getUser(user1.getId());
    assertThat(updatedUser1.getId(), equalTo(user1.getId()));
    assertThat(updatedUser1.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));

    ScimUser updatedUser2 = scimUtils.getUser(user2.getId());
    assertThat(updatedUser2.getId(), equalTo(user2.getId()));
    assertThat(updatedUser2.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));

  }

  @Test
  public void testPatchRemoveNotFoundSamlId() throws Exception {

    ScimUser user = createLennonTestUser();

    ScimUser updates = ScimUser.builder().buildSamlId("fake_idpid", "fake_userid").build();

    scimUtils.patchUser(user.getId(), remove, updates);

    ScimUser updatedUser = scimUtils.getUser(user.getId());
    assertThat(updatedUser.getId(), equalTo(user.getId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
  }
}
