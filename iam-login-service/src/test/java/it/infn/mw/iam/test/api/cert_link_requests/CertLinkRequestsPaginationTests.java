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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK)
public class CertLinkRequestsPaginationTests extends CertLinkRequestsTestUtils {

  private final static String LIST_REQUESTS_URL = "/iam/cert_link_requests/";

  public static final String SUBJECT_TEMPLATE = "CN=test-%03d";

  @Autowired
  private MockMvc mvc;

  void saveNPendingCertLinkRequests(String username, int numRequests) {
    for (int i = 1; i <= numRequests; i++) {
      savePendingCertLinkRequest(TEST_100_USERNAME, String.format(SUBJECT_TEMPLATE, i), TEST_ISSUERDN_OK, null);
    }
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void testNoCertLinkManagersPaginationResult() throws Exception {
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalResults", equalTo(0)))
        .andExpect(jsonPath("$.startIndex", equalTo(1)))
        .andExpect(jsonPath("$.itemsPerPage", equalTo(0)))
        .andExpect(jsonPath("$.Resources", hasSize(0)));
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void testPaginatedAccess() throws Exception {

    saveNPendingCertLinkRequests("test", 20);

    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalResults", equalTo(20)))
        .andExpect(jsonPath("$.startIndex", equalTo(1)))
        .andExpect(jsonPath("$.itemsPerPage", equalTo(10)))
        .andExpect(jsonPath("$.Resources", hasSize(10)))
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-001')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-002')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-003')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-004')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-005')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-006')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-007')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-008')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-009')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-010')]").exists());
    mvc.perform(get(LIST_REQUESTS_URL).param("startIndex", "11")
        .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalResults", equalTo(20)))
        .andExpect(jsonPath("$.startIndex", equalTo(11)))
        .andExpect(jsonPath("$.itemsPerPage", equalTo(10)))
        .andExpect(jsonPath("$.Resources", hasSize(10)))
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-011')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-012')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-013')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-014')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-015')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-016')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-017')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-018')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-019')]").exists())
        .andExpect(jsonPath("$.Resources[?(@.subjectDn=='CN=test-020')]").exists());
  }

}
