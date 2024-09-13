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
package it.infn.mw.iam.test.api.cert_link_requests;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class CertLinkRequestsGetDetailsTests extends CertLinkRequestsTestUtils {

  private static final String GET_DETAILS_URL = "/iam/cert_link_requests/{uuid}";

  @Autowired
  private MockMvc mvc;

  private void getCertLinkRequestDetails() throws Exception {
    CertLinkRequestDTO request =
        savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(request.getUsername())))
      .andExpect(jsonPath("$.subjectDn", equalTo(request.getSubjectDn())))
      .andExpect(jsonPath("$.issuerDn", equalTo(request.getIssuerDn())))
      .andExpect(jsonPath("$.status", equalTo(request.getStatus())))
      .andExpect(jsonPath("$.notes", equalTo(request.getNotes())));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void getCertLinkRequestDetailsAsAdmin() throws Exception {

    getCertLinkRequestDetails();
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void getCertLinkRequestDetailsAsUser() throws Exception {
    CertLinkRequestDTO request =
        savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(request.getUsername())))
      .andExpect(jsonPath("$.subjectDn", equalTo(request.getSubjectDn())))
      .andExpect(jsonPath("$.issuerDn", equalTo(request.getIssuerDn())))
      .andExpect(jsonPath("$.status", equalTo(request.getStatus())));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void getCertLinkRequestDetailsOfAnotherUser() throws Exception {
    CertLinkRequestDTO request =
        savePendingCertLinkRequest(TEST_101_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    // @formatter:off
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithAnonymousUser
  public void getCertLinkRequestDetailsAsAnonymous() throws Exception {
    CertLinkRequestDTO request =
        savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    // @formatter:off
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", containsString("unauthorized")))
      .andExpect(jsonPath("$.error_description", containsString("Full authentication is required")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void getDetailsOfNotExitingCertLinkRequest() throws Exception {

    String fakeRequestUuid = UUID.randomUUID().toString();
    // @formatter:off
    mvc.perform(get(GET_DETAILS_URL, fakeRequestUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("does not exist")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  public void getCertLinkRequestDetailsAsUserWithBothRoles() throws Exception {

    getCertLinkRequestDetails();
  }

}
