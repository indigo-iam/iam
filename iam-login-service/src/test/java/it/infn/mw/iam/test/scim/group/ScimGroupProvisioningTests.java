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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.requests.service.GroupRequestsService;
import it.infn.mw.iam.api.scim.converter.GroupConverter;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.provisioning.ScimGroupProvisioning;
import it.infn.mw.iam.api.scim.provisioning.paging.DefaultScimPageRequest;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScimGroupProvisioningTests {

  private static final String GROUP_URI = ScimUtils.getGroupsLocation();
  private static final String SCIM_CLIENT_ID = "scim-client-rw";
  private static final String SCIM_CLIENT_SECRET = "secret";

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamGroupRepository repo;

  @Mock
  private IamGroupService groupService;

  @Mock
  private IamAccountService accountService;

  @Mock
  private GroupRequestsService groupRequestsService;

  @Mock
  private GroupConverter converter;

  @Mock
  private ScimResourceLocationProvider locationProvider;

  @Mock
  private IamAccountRepository accountRepo;

  private String filter = "groupName eq test";

  @InjectMocks
  private ScimGroupProvisioning scimGroupProvisioning;

  private String scimAccessToken;

  @BeforeEach
  void setup() {
    scimAccessToken = null;
  }

  private ResultActions performScim(MockHttpServletRequestBuilder request) throws Exception {

    if (scimAccessToken == null) {
      scimAccessToken = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper,
          SCIM_CLIENT_ID, SCIM_CLIENT_SECRET, "scim:read", "scim:write");
    }

    return mvc.perform(request.header(AUTHORIZATION, "Bearer " + scimAccessToken));
  }

  @Test
  void testGetGroupNotFoundResponse() throws Exception {

    String randomUuid = UUID.randomUUID().toString();

    performScim(get(GROUP_URI + "/{uuid}", randomUuid).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNotFound())
      .andExpect(content().contentType(APPLICATION_JSON_VALUE))
      .andExpect(jsonPath("$.status", equalTo("404")))
      .andExpect(jsonPath("$.detail", equalTo("No group mapped to id '" + randomUuid + "'")));
  }

  @Test
  void testUpdateGroupNotFoundResponse() throws Exception {

    String randomUuid = UUID.randomUUID().toString();
    ScimGroup group = ScimGroup.builder("engineers").id(randomUuid).build();

    performScim(put(GROUP_URI + "/{uuid}", randomUuid).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(group))).andExpect(status().isNotFound())
        .andExpect(content().contentType(APPLICATION_JSON_VALUE))
        .andExpect(jsonPath("$.status", equalTo("404")))
        .andExpect(jsonPath("$.detail", equalTo("No group mapped to id '" + randomUuid + "'")));
  }

  @Test
  void testGetExistingGroup() throws Exception {

    String groupId = "c617d586-54e6-411d-8e38-64967798fa8a";

    performScim(get(GROUP_URI + "/{uuid}", groupId).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(jsonPath("$.id", equalTo(groupId)))
      .andExpect(jsonPath("$.displayName", equalTo("Production")))
      .andExpect(jsonPath("$.meta.resourceType", equalTo("Group")))
      .andExpect(
          jsonPath("$.meta.location", equalTo("http://localhost:8080/scim/Groups/" + groupId)))
      .andExpect(jsonPath("$.schemas",
          hasItems(ScimGroup.GROUP_SCHEMA, ScimConstants.INDIGO_GROUP_SCHEMA)));
  }

  @Test
  void testCreateAndDeleteGroupSuccessResponse() throws Exception {

    String name = "engineers";
    ScimGroup group = ScimGroup.builder(name).build();

    String result = performScim(post(GROUP_URI).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(group))).andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    ScimGroup createdGroup = objectMapper.readValue(result, ScimGroup.class);

    performScim(get(createdGroup.getMeta().getLocation())).andExpect(status().isOk())
      .andExpect(jsonPath("$.displayName", equalTo(name)));

    performScim(delete(createdGroup.getMeta().getLocation())).andExpect(status().isNoContent());
  }

  @Test
  void testUpdateGroupDisplaynameSuccessResponse() throws Exception {

    ScimGroup requestedGroup = ScimGroup.builder("engineers").build();

    String result = performScim(post(GROUP_URI).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(requestedGroup))).andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    ScimGroup createdGroup = objectMapper.readValue(result, ScimGroup.class);
    requestedGroup = ScimGroup.builder("engineers_updated").build();

    performScim(put(createdGroup.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(requestedGroup))).andExpect(status().isOk())
        .andExpect(jsonPath("$.displayName", equalTo(requestedGroup.getDisplayName())));

    performScim(delete(createdGroup.getMeta().getLocation())).andExpect(status().isNoContent());
  }

  @Test
  void testCreateGroupEmptyDisplayNameValidationError() throws Exception {

    ScimGroup group = ScimGroup.builder("").build();

    performScim(post(GROUP_URI).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(group))).andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.detail", containsString("scimGroup.displayName : must not be blank")));
  }


  @Test
  void testUpdateGroupEmptyDisplayNameValidationError() throws Exception {

    ScimGroup requestedGroup = ScimGroup.builder("engineers").build();

    String result = performScim(post(GROUP_URI).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(requestedGroup))).andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    ScimGroup createdGroup = objectMapper.readValue(result, ScimGroup.class);
    requestedGroup = ScimGroup.builder("").build();

    performScim(put(createdGroup.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsBytes(requestedGroup))).andExpect(status().isBadRequest());

    performScim(delete(createdGroup.getMeta().getLocation())).andExpect(status().isNoContent());
  }

  @Test
  void testUpdateGroupAlreadyUsedDisplaynameError() throws Exception {

    String result = performScim(post(GROUP_URI).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(ScimGroup.builder("engineers").build())))
        .andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    ScimGroup engineers = objectMapper.readValue(result, ScimGroup.class);

    result = performScim(post(GROUP_URI).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(ScimGroup.builder("artists").build())))
        .andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    ScimGroup artists = objectMapper.readValue(result, ScimGroup.class);

    performScim(put(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(ScimGroup.builder("artists").build())))
        .andExpect(status().isConflict());

    performScim(delete(engineers.getMeta().getLocation())).andExpect(status().isNoContent());

    performScim(delete(artists.getMeta().getLocation())).andExpect(status().isNoContent());
  }

  @Test
  void groupDescriptionIsRendered() throws Exception {

    final String groupId = UUID.randomUUID().toString();
    final String groupName = "group-with-description";
    final String groupDesc = "A group description";

    IamGroup group = new IamGroup();
    group.setUuid(groupId);
    group.setName(groupName);
    group.setDescription(groupDesc);
    group.setCreationTime(new Date());
    group.setLastUpdateTime(new Date());

    repo.save(group);

    performScim(get("/scim/Groups/{id}", groupId).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.displayName", is(groupName)))
      .andExpect(jsonPath("$.urn:indigo-dc:scim:schemas:IndigoGroup").exists())
      .andExpect(jsonPath("$.urn:indigo-dc:scim:schemas:IndigoGroup.description", is(groupDesc)));
  }

  @Test
  void groupListFilterReference() {

    Logger logger = (Logger) LoggerFactory.getLogger(ScimGroupProvisioning.class);

    @SuppressWarnings("unchecked")
    Appender<ILoggingEvent> mockAppender = mock(Appender.class);

    logger.addAppender(mockAppender);

    List<IamGroup> groupEntities = new ArrayList<>();
    IamGroup group = new IamGroup();
    group.setUuid(UUID.randomUUID().toString());
    group.setName("test");
    groupEntities.add(group);

    Page<IamGroup> page = new PageImpl<>(groupEntities);

    when(groupService.findAll(any())).thenReturn(page);

    DefaultScimPageRequest pageRequest =
        new DefaultScimPageRequest.Builder().count(30).startIndex(0).build();

    ScimListResponse<ScimGroup> response = scimGroupProvisioning.list(pageRequest, filter);

    ArgumentCaptor<ILoggingEvent> captor = ArgumentCaptor.forClass(ILoggingEvent.class);
    verify(mockAppender, atLeastOnce()).doAppend(captor.capture());

    boolean warningFound = captor.getAllValues()
      .stream()
      .anyMatch(event -> event.getLevel().toString().equals("WARN") && event.getFormattedMessage()
        .contains("Unsupported filtered list, reverting to default and ignoring filter"));

    assertTrue(warningFound);

    assertNotNull(response);
    assertEquals(1, response.getResources().size());

    logger.detachAppender(mockAppender);
  }
}
