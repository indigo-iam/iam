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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.type.TypeReference;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK)
public class CertLinkRequestsListTests extends CertLinkRequestsTestUtils {

  private static final String LIST_REQUESTS_URL = "/iam/cert_link_requests/";

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    savePendingCertLinkRequest(TEST_101_USERNAME, "CN=test1", "CN=ca", null);
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void listCertLinkRequestAsAdmin() throws Exception {

    // @formatter:off
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.Resources", hasSize(2)));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void filterByUsernameAsAdmin() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("username", TEST_101_USERNAME))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(1)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(TEST_101_USERNAME));
    }
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void filterByStatusAsAdmin() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("status", IamRequestStatus.PENDING.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.Resources", hasSize(2)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getStatus(), equalTo(IamRequestStatus.PENDING.name()));
    }
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void filterBySubjectAsAdmin() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("subjectDn", TEST_SUBJECTDN_OK))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(1)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getSubjectDn(), equalTo(TEST_SUBJECTDN_OK));
    }
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void listCertLinkRequestAsUser() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(1)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(TEST_100_USERNAME));
    }
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void listCertLinkRequestOfAnotherUserIgnoreFilter() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("username", TEST_101_USERNAME))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(TEST_100_USERNAME));
    }
  }

  @Test
  @WithAnonymousUser
  public void listCertLinkRequestAsAnonymous() throws Exception {
    // @formatter:off
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void filterByUsernameAndStatusAsAdmin() throws Exception {
    String testStatus = IamRequestStatus.PENDING.name();
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("username", TEST_100_USERNAME)
        .param("status", testStatus))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(1)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(TEST_100_USERNAME));
      assertThat(elem.getStatus(), equalTo(testStatus));
    }
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void filterBySubjectAndStatusAsAdmin() throws Exception {
    String testStatus = IamRequestStatus.PENDING.name();
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("subjectDn", TEST_SUBJECTDN_OK)
        .param("status", testStatus))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(1)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<CertLinkRequestDTO> result = mapper.readValue(response,
        new TypeReference<ListResponseDTO<CertLinkRequestDTO>>() {
        });

    for (CertLinkRequestDTO elem : result.getResources()) {
      assertThat(elem.getSubjectDn(), equalTo(TEST_SUBJECTDN_OK));
      assertThat(elem.getStatus(), equalTo(testStatus));
    }
  }

  @Test
  @WithMockUser(roles = { "ADMIN", "USER" }, username = TEST_ADMIN)
  public void listRequestAsUserWithBothRoles() throws Exception {
    // @formatter:off
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.Resources", hasSize(2)));
    // @formatter:on
  }
}
