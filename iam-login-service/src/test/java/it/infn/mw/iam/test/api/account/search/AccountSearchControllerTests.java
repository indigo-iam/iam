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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
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
import org.springframework.data.domain.Page;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AccountSearchControllerTests {

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

  @Autowired
  private UserConverter userConverter;

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
  public void getFirstPageOfAllUsers() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response = mapper.readValue(
        mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getSecondPageOfAllUsers() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response = mapper.readValue(
        mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("startIndex", String.valueOf(DEFAULT_ITEMS_PER_PAGE))).andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersWithCustomStartIndexAndCount() throws JsonParseException,
      JsonMappingException, UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();
    int startIndex = 3;
    int count = 2;

    ListResponseDTO<ScimUser> response = mapper.readValue(
        mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("startIndex", String.valueOf(startIndex)).param("count", String.valueOf(count)))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(count));
    assertThat(response.getStartIndex(), equalTo(startIndex));
    assertThat(response.getItemsPerPage(), equalTo(count));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getCountOfAllUsers() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("count", "0"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources(), is(empty()));
    assertThat(response.getStartIndex(), equalTo(null));
    assertThat(response.getItemsPerPage(), equalTo(null));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getFirstFilteredPageOfUsers() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    OffsetPageable op = new OffsetPageable(0, 10);
    Page<IamAccount> page = accountRepository.findByFilter("admin", op);

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("filter", "admin"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});

    assertThat(response.getResources().size(), equalTo(2));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(2));

    List<ScimUser> expectedUsers = Lists.newArrayList();

    page.getContent().forEach(u -> expectedUsers.add(userConverter.dtoFromEntity(u)));
    assertThat(response.getResources().containsAll(expectedUsers), equalTo(true));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getCountOfFilteredUsers() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.countByFilter("admin");

    ListResponseDTO<ScimUser> response =
        mapper.readValue(
            mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
                .param("count", "0").param("filter", "admin")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources(), is(empty()));
    assertThat(response.getStartIndex(), equalTo(null));
    assertThat(response.getItemsPerPage(), equalTo(null));
  }

  @Test
  public void getUsersAsAnonymousUser() throws Exception {
    mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE))
        .andExpect(status().isUnauthorized());
  }
  
  @Test
  @WithMockUser(username="test", roles= {"USER", "GM:c617d586-54e6-411d-8e38-649677980001"})
  public void getUsersAsGroupManager() throws Exception {
    mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE))
    .andExpect(status().isOk());
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"})
  public void getUsersAsAuthenticatedUser() throws Exception {
    mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE))
        .andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersWithNegativeStartIndex() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("startIndex", "-1"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersWithStartIndexZero() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("startIndex", "0"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersWithCountBiggerThanPageSize() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response =
        mapper.readValue(
            mvc.perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
                .param("count", "" + DEFAULT_ITEMS_PER_PAGE * 2)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void getUsersWithNegativeCount() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    long expectedSize = accountRepository.count();

    ListResponseDTO<ScimUser> response = mapper.readValue(mvc
        .perform(get(ACCOUNT_SEARCH_ENDPOINT).contentType(APPLICATION_JSON_CONTENT_TYPE)
            .param("count", "-1"))
        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),
        new TypeReference<ListResponseDTO<ScimUser>>() {});
    assertThat(response.getTotalResults(), equalTo(expectedSize));
    assertThat(response.getResources().size(), equalTo(DEFAULT_ITEMS_PER_PAGE));
    assertThat(response.getStartIndex(), equalTo(1));
    assertThat(response.getItemsPerPage(), equalTo(DEFAULT_ITEMS_PER_PAGE));
  }
}
