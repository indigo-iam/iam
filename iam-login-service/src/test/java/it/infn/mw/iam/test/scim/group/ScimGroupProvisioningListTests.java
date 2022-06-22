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
package it.infn.mw.iam.test.scim.group;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read"})
public class ScimGroupProvisioningListTests {

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private final static String GROUP_URI = ScimUtils.getGroupsLocation();

  private Integer totalResults = 0;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
    totalResults = (int) groupRepo.count();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testNoParameterListRequest() throws Exception {

    mvc.perform(get(GROUP_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(totalResults)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(totalResults))));
  }

  @Test
  public void testCountAs8Returns8Items() throws Exception {
    Integer count = 8;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", count.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(count)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(count))));
    //@formatter:on
  }

  @Test
  public void testCount1Returns1Item() throws Exception {
    Integer count = 1;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", count.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(count)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(count))));
    //@formatter:on
  }

  @Test
  public void testNegativeCountBecomesZero() throws Exception {
    Integer count = -10;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", count.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage").doesNotExist())
      .andExpect(jsonPath("$.startIndex").doesNotExist())
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", is(empty())));
    //@formatter:on
  }

  @Test
  public void testInvalidStartIndex() throws Exception {
    Integer startIndex = 23;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("startIndex", startIndex.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(0)))
      .andExpect(jsonPath("$.startIndex", equalTo(startIndex)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(0))));
    //@formatter:on
  }

  @Test
  public void testRightEndPagination() throws Exception {
    Integer count = 10;
    Integer startIndex = 17;
    Integer items = totalResults - startIndex + 1;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", count.toString())
        .param("startIndex", startIndex.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(items)))
      .andExpect(jsonPath("$.startIndex", equalTo(startIndex)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(items))));
    //@formatter:on
  }

  @Test
  public void testLastElementPagination() throws Exception {
    Integer count = 2;
    Integer startIndex = 22;
    Integer items = totalResults - startIndex + 1;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", count.toString())
        .param("startIndex", startIndex.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(items)))
      .andExpect(jsonPath("$.startIndex", equalTo(startIndex)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(items))));
    //@formatter:on
  }

  @Test
  public void testFirstElementPagination() throws Exception {
    Integer count = 5;
    Integer startIndex = 1;

    //@formatter:off
    mvc.perform(get(GROUP_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", count.toString())
        .param("startIndex", startIndex.toString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(totalResults)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(count)))
      .andExpect(jsonPath("$.startIndex", equalTo(startIndex)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(count))));
    //@formatter:on
  }
}
