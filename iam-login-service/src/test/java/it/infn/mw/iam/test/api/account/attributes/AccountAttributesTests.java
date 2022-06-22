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
package it.infn.mw.iam.test.api.account.attributes;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.AttributeDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AccountAttributesTests {

  public static final ResultMatcher OK = status().isOk();
  public static final ResultMatcher NO_CONTENT = status().isNoContent();
  public static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  public static final ResultMatcher FORBIDDEN = status().isForbidden();
  public static final ResultMatcher NOT_FOUND = status().isNotFound();

  public static final String TEST_USER = "test";
  public static final String TEST_100_USER = "test_100";

  public static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";
  public static final String ACCOUNT_NOT_FOUND = "Account not found";

  public static final String ACCOUNT_ATTR_URL_TEMPLATE = "/iam/account/{id}/attributes";

  public static final String ATTR_NAME = "attr.example";
  public static final String ATTR_VALUE = "somevalue";

  public static final String ATTR_NAME_TEMPLATE = "attr.name.%d";
  public static final String ATTR_VALUE_TEMPLATE = "attr.value.%d";

  public static final TypeReference<List<AttributeDTO>> LIST_OF_ATTRIBUTE_DTO =
      new TypeReference<List<AttributeDTO>>() {};

  @Autowired
  private IamAccountRepository repo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private ObjectMapper mapper;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @Test
  @WithAnonymousUser
  public void managingAttributesRequiresAuthenticatedUser() throws Exception {

    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));


    final String UUID = testAccount.getUuid();

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, UUID)).andExpect(UNAUTHORIZED);

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc
      .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, UUID).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(UNAUTHORIZED);

    mvc.perform(delete(ACCOUNT_ATTR_URL_TEMPLATE, UUID).param("name", ATTR_NAME))
      .andExpect(UNAUTHORIZED);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void aUserCanListHisAttributes() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, testAccount.getUuid())).andExpect(OK);
  }
  
  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void managingAttributesRequiresPrivilegedUser() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_100_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));


    final String UUID = testAccount.getUuid();

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, UUID)).andExpect(FORBIDDEN);

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc
      .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, UUID).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(FORBIDDEN);

    mvc.perform(delete(ACCOUNT_ATTR_URL_TEMPLATE, UUID).param("name", ATTR_NAME))
      .andExpect(FORBIDDEN);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void gettingAttributesWorksForAdminUser() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));


    final String UUID = testAccount.getUuid();

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, UUID)).andExpect(OK);

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, UUID))
      .andExpect(OK)
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").isEmpty());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void setAttributeWorks() throws Exception {

    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    final String UUID = testAccount.getUuid();

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc
      .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, UUID).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(OK);

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, UUID))
      .andExpect(OK)
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$[0].name", is(ATTR_NAME)))
      .andExpect(jsonPath("$[0].value", is(ATTR_VALUE)));

    attr.setValue(null);

    mvc
      .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, UUID).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(OK);

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, UUID))
      .andExpect(OK)
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$", hasSize(1)))
      .andExpect(jsonPath("$[0].name", is(ATTR_NAME)))
      .andExpect(jsonPath("$[0].value", nullValue()));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void deleteAttributeWorks() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    final String UUID = testAccount.getUuid();

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc
      .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, UUID).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(OK);

    mvc.perform(delete(ACCOUNT_ATTR_URL_TEMPLATE, UUID).param("name", ATTR_NAME))
      .andExpect(NO_CONTENT);

    // A delete succeeds even if the attribute isn't there
    mvc.perform(delete(ACCOUNT_ATTR_URL_TEMPLATE, UUID).param("name", ATTR_NAME))
      .andExpect(NO_CONTENT);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void nonExistingAccountIsHandledCorrectly() throws Exception {
    String randomUuid = UUID.randomUUID().toString();
    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    final ResultMatcher accountNotFound = jsonPath("$.error", containsString(ACCOUNT_NOT_FOUND));

    mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, randomUuid))
      .andExpect(NOT_FOUND)
      .andExpect(accountNotFound);

    mvc
      .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, randomUuid).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(NOT_FOUND)
      .andExpect(accountNotFound);

    mvc.perform(delete(ACCOUNT_ATTR_URL_TEMPLATE, randomUuid).param("name", ATTR_NAME))
      .andExpect(NOT_FOUND)
      .andExpect(accountNotFound);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void multiAttributeSetTest() throws Exception {

    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamAccount test100Account =
        repo.findByUsername(TEST_100_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    final String TEST_UUID = testAccount.getUuid();

    final String TEST_100_UUID = test100Account.getUuid();

    List<AttributeDTO> attrs = Lists.newArrayList();

    for (int i = 0; i < 10; i++) {
      attrs.add(
          AttributeDTO.newInstance(format(ATTR_NAME_TEMPLATE, i), format(ATTR_VALUE_TEMPLATE, i)));
    }

    for (AttributeDTO a : attrs) {
      mvc
        .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, TEST_UUID).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(a)))
        .andExpect(OK);

      mvc
        .perform(put(ACCOUNT_ATTR_URL_TEMPLATE, TEST_100_UUID).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(a)))
        .andExpect(OK);
    }


    for (String uuid : asList(TEST_UUID, TEST_100_UUID)) {
      String resultString = mvc.perform(get(ACCOUNT_ATTR_URL_TEMPLATE, uuid))
        .andExpect(OK)
        .andExpect(jsonPath("$").isArray())
        .andExpect(jsonPath("$", hasSize(10)))
        .andReturn()
        .getResponse()
        .getContentAsString();

      List<AttributeDTO> results = mapper.readValue(resultString, LIST_OF_ATTRIBUTE_DTO);
      attrs.forEach(a -> assertThat(results, hasItem(a)));
    }
  }
}
