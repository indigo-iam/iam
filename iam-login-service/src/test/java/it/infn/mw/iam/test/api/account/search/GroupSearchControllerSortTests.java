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
package it.infn.mw.iam.test.api.account.search;

import static it.infn.mw.iam.api.account.search.AbstractSearchController.DEFAULT_ITEMS_PER_PAGE;
import static it.infn.mw.iam.api.account.search.GroupSearchController.GROUP_SEARCH_ENDPOINT;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class GroupSearchControllerSortTests {

  public static final String APPLICATION_JSON_CONTENT_TYPE = "application/json";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamGroupRepository groupRepository;

  @Before
  public void setup() {
    mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getGroupsWithInvalidSortDirection() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimGroup> response = mapper.readValue(mvc
        .perform(get(GROUP_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortDirection", "pippo"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimGroup>>() {});
    assertThat(response.getTotalResults(), equalTo(groupRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByNameAsc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getGroupsSortByNameAsc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimGroup> response = mapper.readValue(mvc
        .perform(get(GROUP_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "name").param("sortDirection", "asc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimGroup>>() {});
    assertThat(response.getTotalResults(), equalTo(groupRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByNameAsc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getGroupsSortByNameDesc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimGroup> response = mapper.readValue(mvc
        .perform(get(GROUP_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "name").param("sortDirection", "desc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimGroup>>() {});
    assertThat(response.getTotalResults(), equalTo(groupRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByNameDesc(response.getResources());
  }

  private void verifySortIsByNameAsc(List<ScimGroup> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimGroup previous = receivedUsers.get(i - 1);
      ScimGroup current = receivedUsers.get(i);
      assertThat(previous.getDisplayName(), lessThanOrEqualTo(current.getDisplayName()));
    }
  }

  private void verifySortIsByNameDesc(List<ScimGroup> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimGroup previous = receivedUsers.get(i - 1);
      ScimGroup current = receivedUsers.get(i);
      assertThat(previous.getDisplayName(), greaterThanOrEqualTo(current.getDisplayName()));
    }
  }
}
