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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
public class CertLinkRequestsDeleteTests extends CertLinkRequestsTestUtils {

  private static final String DELETE_URL = "/iam/cert_link_requests/{uuid}";

  @Autowired
  private MockMvc mvc;

  private void deletePendingCertLinkRequest() throws Exception {
    CertLinkRequestDTO request =
        savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isNoContent());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void deletePendingCertLinkRequestAsAdmin() throws Exception {

    deletePendingCertLinkRequest();
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void deleteApprovedCertLinkRequestAsAdmin() throws Exception {
    CertLinkRequestDTO request =
        saveApprovedCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, "");
    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isNoContent());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void deletePendingCertLinkRequestAsUser() throws Exception {

    deletePendingCertLinkRequest();
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void deleteApprovedCertLinkRequestAsUser() throws Exception {
    CertLinkRequestDTO request =
        saveApprovedCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, "");

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void deleteCertLinkRequestOfAnotherUser() throws Exception {

    CertLinkRequestDTO request =
        savePendingCertLinkRequest("test_101", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithAnonymousUser
  public void deleteCertLinkRequestAsAnonymous() throws Exception {

    CertLinkRequestDTO request =
        savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void deleteNotExitingCertLinkRequest() throws Exception {

    String fakeRequestUuid = UUID.randomUUID().toString();

    // @formatter:off
    mvc.perform(delete(DELETE_URL, fakeRequestUuid))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  public void deletePendingCertLinkRequestAsUserWithBothRoles() throws Exception {

    deletePendingCertLinkRequest();
  }
}
