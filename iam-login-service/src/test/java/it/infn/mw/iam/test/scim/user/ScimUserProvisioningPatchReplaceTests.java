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

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
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
public class ScimUserProvisioningPatchReplaceTests extends ScimUserTestSupport {

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
  public void testReplaceEmailWithEmptyValue() throws Exception {
    ScimUser testUser = createLennonTestUser();
    ScimUser updates = ScimUser.builder().buildEmail("").build();

    scimUtils.patchUser(testUser.getId(), replace, updates, BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString(": must not be empty")));
  }

  @Test
  public void testReplaceEmailWithNullValue() throws Exception {

    ScimUser testUser = createLennonTestUser();
    ScimUser updates = ScimUser.builder().buildEmail(null).build();

    scimUtils.patchUser(testUser.getId(), replace, updates, BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString(": must not be empty")));
  }

  @Test
  public void testReplaceEmailWithSameValue() throws Exception {

    ScimUser testUser = createLennonTestUser();
    ScimUser updates =
        ScimUser.builder().buildEmail(testUser.getEmails().get(0).getValue()).build();

    scimUtils.patchUser(testUser.getId(), replace, updates);
  }

  @Test
  public void testReplaceEmailWithInvalidValue() throws Exception {

    ScimUser testUser = createLennonTestUser();
    ScimUser updates = ScimUser.builder().buildEmail("fakeEmail").build();

    scimUtils.patchUser(testUser.getId(), replace, updates, BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("Please provide a valid email address")));
  }

  @Test
  public void testReplacePicture() throws Exception {
    ScimUser testUser = createLennonTestUser();

    assertThat(testUser.getPhotos(), hasSize(equalTo(1)));
    assertThat(testUser.getPhotos().get(0).getValue(), equalTo(PICTURES.get(0)));

    ScimUser updates = ScimUser.builder().buildPhoto(PICTURES.get(1)).build();

    scimUtils.patchUser(testUser.getId(), replace, updates);

    ScimUser updatedUser = scimUtils.getUser(testUser.getId());
    assertThat(updatedUser.getPhotos(), hasSize(equalTo(1)));
    assertThat(updatedUser.getPhotos().get(0).getValue(), equalTo(PICTURES.get(1)));
  }

  @Test
  public void testReplaceUsername() throws Exception {

    ScimUser testUser = createLennonTestUser();
    final String ANOTHERUSER_USERNAME = "test";

    ScimUser updates = ScimUser.builder().userName(ANOTHERUSER_USERNAME).build();

    scimUtils.patchUser(testUser.getId(), replace, updates, CONFLICT);
  }

  @Test
  public void testPatchReplaceSshKeyNotSupported() throws Exception {
    ScimUser testUser = createLennonTestUser();

    String keyValue = testUser.getIndigoUser().getSshKeys().get(0).getValue();

    ScimUser updates = ScimUser.builder()
      .addSshKey(ScimSshKey.builder().value(keyValue).display("NEW LABEL").build())
      .build();

    scimUtils.patchUser(testUser.getId(), replace, updates, BAD_REQUEST);
  }

  @Test
  public void testPatchReplaceX509CertificateNotSupported() throws Exception {
    ScimUser testUser = createLennonTestUser();
    String certValue = testUser.getIndigoUser().getCertificates().get(0).getPemEncodedCertificate();

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display("NEW LABEL")
      .pemEncodedCertificate(certValue)
      .primary(true)
      .build();

    ScimUser updates = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(testUser.getId(), replace, updates, HttpStatus.BAD_REQUEST);
  }
}
