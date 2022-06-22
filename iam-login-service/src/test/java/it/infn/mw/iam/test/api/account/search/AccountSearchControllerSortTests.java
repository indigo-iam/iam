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
import static it.infn.mw.iam.api.account.search.AccountSearchController.ACCOUNT_SEARCH_ENDPOINT;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AccountSearchControllerSortTests {

  public static final String APPLICATION_JSON_CONTENT_TYPE = "application/json";

  @Autowired
  private WebApplicationContext context;

  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamAccountRepository accountRepository;

  @Before
  public void setup() {
    mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    mockOAuth2Filter.cleanupSecurityContext();
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log())
        .build();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersWithInvalidSortDirection() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortDirection", "pippo"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByNameAsc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersSortByNameAsc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "name").param("sortDirection", "asc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByNameAsc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersSortByNameDesc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "name").param("sortDirection", "desc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByNameDesc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersSortByEmailAsc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "email").param("sortDirection", "asc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByEmailAsc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersSortByEmailDesc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "email").param("sortDirection", "desc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByEmailDesc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersSortByCreationTimeAsc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "creation").param("sortDirection", "asc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByCreationTimeAsc(response.getResources());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersSortByCreationTimeDesc() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("sortBy", "creation").param("sortDirection", "desc"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(accountRepository.count()));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));

    verifySortIsByCreationTimeDesc(response.getResources());
  }

  private void verifySortIsByNameAsc(List<ScimUser> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimUser previous = receivedUsers.get(i - 1);
      ScimUser current = receivedUsers.get(i);
      assertThat(previous.getName().getGivenName(),
          lessThanOrEqualTo(current.getName().getGivenName()));
      if (previous.getName().getGivenName().equals(current.getName().getGivenName())) {
        assertThat(previous.getName().getFamilyName(),
            lessThanOrEqualTo(current.getName().getFamilyName()));
      }
    }
  }

  private void verifySortIsByNameDesc(List<ScimUser> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimUser previous = receivedUsers.get(i - 1);
      ScimUser current = receivedUsers.get(i);
      assertThat(previous.getName().getGivenName(),
          greaterThanOrEqualTo(current.getName().getGivenName()));
      if (previous.getName().getGivenName().equals(current.getName().getGivenName())) {
        assertThat(previous.getName().getFamilyName(),
            greaterThanOrEqualTo(current.getName().getFamilyName()));
      }
    }
  }

  private void verifySortIsByEmailAsc(List<ScimUser> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimUser previous = receivedUsers.get(i - 1);
      ScimUser current = receivedUsers.get(i);
      assertThat(previous.getEmails().get(0).getValue(),
          lessThanOrEqualTo(current.getEmails().get(0).getValue()));
    }
  }

  private void verifySortIsByEmailDesc(List<ScimUser> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimUser previous = receivedUsers.get(i - 1);
      ScimUser current = receivedUsers.get(i);
      assertThat(previous.getEmails().get(0).getValue(),
          greaterThanOrEqualTo(current.getEmails().get(0).getValue()));
    }
  }

  private void verifySortIsByCreationTimeAsc(List<ScimUser> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimUser previous = receivedUsers.get(i - 1);
      ScimUser current = receivedUsers.get(i);
      assertThat(previous.getMeta().getCreated(),
          lessThanOrEqualTo(current.getMeta().getCreated()));
    }
  }

  private void verifySortIsByCreationTimeDesc(List<ScimUser> receivedUsers) {

    if (receivedUsers.size() <= 1) {
      return;
    }
    for (int i = 1; i < receivedUsers.size(); i++) {
      ScimUser previous = receivedUsers.get(i - 1);
      ScimUser current = receivedUsers.get(i);
      assertThat(previous.getMeta().getCreated(),
          greaterThanOrEqualTo(current.getMeta().getCreated()));
    }
  }
}
