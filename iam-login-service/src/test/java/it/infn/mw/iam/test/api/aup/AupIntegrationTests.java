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
package it.infn.mw.iam.test.api.aup;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.util.DateEqualModulo1Second;
import it.infn.mw.iam.test.util.MockTimeProvider;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class AupIntegrationTests extends AupTestSupport {

  private final String INVALID_AUP_URL =
      "https://iam.local.io/\"</script><script>alert(8);</script>";

  private static final String DEFAULT_AUP_TEXT = null;
  private static final String DEFAULT_AUP_URL = "http://updated-aup-text.org/";
  private static final String DEFAULT_AUP_DESC = "desc";


  @Autowired
  private WebApplicationContext context;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private AupConverter converter;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockTimeProvider mockTimeProvider;

  private MockMvc mvc;



  @Before
  public void setup() {
    mvc =
        MockMvcBuilders.webAppContextSetup(context).alwaysDo(log()).apply(springSecurity()).build();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private void verifyAupCreationSuccess(AupDTO aup) throws Exception {
    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());

    String aupJson = mvc.perform(get("/iam/aup"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    AupDTO createdAup = mapper.readValue(aupJson, AupDTO.class);

    assertThat(createdAup.getSignatureValidityInDays(), equalTo(aup.getSignatureValidityInDays()));
    assertThat(createdAup.getAupRemindersInDays(), equalTo(""));
  }

  private void verifyAupCreationFailureWithBadRequest(AupDTO aup, String errorMessage)
      throws Exception {
    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(errorMessage)));
  }

  private void createAup(AupDTO aup) throws Exception {
    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());
  }

  private void verifyAupUpdateFailureWithBadRequest(AupDTO aup, String errorMessage)
      throws Exception {
    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(errorMessage)));
  }

  @Test
  public void noAupDefinedResultsin404() throws Exception {
    mvc.perform(get("/iam/aup"))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo(AupNotFoundError.AUP_NOT_DEFINED)));
  }

  @Test
  public void aupIsReturnedIfDefined() throws Exception {

    IamAup defaultAup = buildDefaultAup();
    aupRepo.save(defaultAup);

    mvc.perform(get("/iam/aup")).andExpect(status().isOk());
  }

  @Test
  public void aupCreationRequiresAuthenticatedUser() throws Exception {
    Date now = new Date();
    String reminders = "1,15,30";
    AupDTO aup =
        new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, DEFAULT_AUP_DESC, -1L, now, now, reminders);

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void aupCreationRequiresAdminPrivileges() throws Exception {
    Date now = new Date();
    String reminders = "1,15,30";
    AupDTO aup =
        new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, DEFAULT_AUP_DESC, -1L, now, now, reminders);

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("Access is denied")));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUrlIsRequired() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());
    aup.setUrl(null);

    verifyAupCreationFailureWithBadRequest(aup, "Invalid AUP: the AUP URL cannot be blank");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUrlIsNotAValidUrl() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());
    aup.setUrl("Not-a-URL");

    verifyAupCreationFailureWithBadRequest(aup, "Invalid AUP: the AUP URL is not valid");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUrlQueryNotAllowed() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());
    aup.setUrl("http://aup-url.org/with?query=value");

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: query string not allowed in the AUP URL");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUrlInvalidHTMLTags() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    aup.setUrl(INVALID_AUP_URL);

    verifyAupCreationFailureWithBadRequest(aup, "Invalid AUP: the AUP URL is not valid");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupDescriptionNoLongerThan128Chars() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());
    String longDescription = Strings.repeat("xxxx", 33);
    aup.setDescription(longDescription);

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: the description string must be at most 128 characters long");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresSignatureValidityDays() throws Exception {
    String reminders = "1,15,30";
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, null, null, null, reminders);

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup, "Invalid AUP: signatureValidityInDays is required");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresPositiveSignatureValidityDays() throws Exception {
    String reminders = "1,15,30";
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, -1L, null, null, reminders);
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: signatureValidityInDays must be >= 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationFailsIfRemindersAreNotEmptyOrNullAndfSignatureValidityIsZero()
      throws Exception {
    String reminders = "1,15,30";
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 0L, null, null, reminders);
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays cannot be set if signatureValidityInDays is 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationSetsEmptyValueForRemindersIfNullAndSignatureValidityIsZero()
      throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 0L, null, null, null);

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationSuccess(aup);
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationSetsEmptyValueForRemindersIfNullAndSignatureValidityIsNotZero()
      throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 3L, null, null, null);
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays must be set when signatureValidityInDays is greater than 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationFailsIfRemindersAreEmptyAndSignatureValidityIsNonZero() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 3L, null, null, "");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: non-integer value found for aupRemindersInDays");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationWorksIfRemindersAreEmptyAndSignatureValidityIsZero() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 0L, null, null, "");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationSuccess(aup);
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresEmptyOrNullRemindersIfSignatureValidityIsZero() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 0L, null, null, "ciao");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays cannot be set if signatureValidityInDays is 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresNoLettersInAupRemindersDays() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 3L, null, null, "ciao");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: non-integer value found for aupRemindersInDays");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresNoZeroInAupRemindersDays() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 3L, null, null, "0");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: zero or negative values for reminders are not allowed");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresPositiveAupRemindersDays() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 3L, null, null, "-22");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: zero or negative values for reminders are not allowed");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresNoDuplicationInAupRemindersDays() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 31L, null, null, "30,15,15");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: duplicate values for reminders are not allowed");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationRequiresAupRemindersSmallerThanSignatureValidityDays() throws Exception {
    AupDTO aup = new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 3L, null, null, "4");
    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    verifyAupCreationFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays must be smaller than signatureValidityInDays");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationWorks() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    createAup(aup);


    String aupJson = mvc.perform(get("/iam/aup"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    AupDTO createdAup = mapper.readValue(aupJson, AupDTO.class);

    DateEqualModulo1Second creationAndLastUpdateTimeMatcher = new DateEqualModulo1Second(now);
    assertThat(createdAup.getUrl(), equalTo(aup.getUrl()));
    assertThat(createdAup.getDescription(), equalTo(aup.getDescription()));
    assertThat(createdAup.getSignatureValidityInDays(), equalTo(aup.getSignatureValidityInDays()));
    assertThat(createdAup.getCreationTime(), creationAndLastUpdateTimeMatcher);
    assertThat(createdAup.getLastUpdateTime(), creationAndLastUpdateTimeMatcher);
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void whiteSpacesAllowedAmongAupRemindersDays() throws Exception {
    AupDTO aup =
        new AupDTO(DEFAULT_AUP_URL, DEFAULT_AUP_TEXT, null, 31L, null, null, " 30, 15, 7 ");

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    createAup(aup);


    String aupJson = mvc.perform(get("/iam/aup"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    AupDTO createdAup = mapper.readValue(aupJson, AupDTO.class);

    DateEqualModulo1Second creationAndLastUpdateTimeMatcher = new DateEqualModulo1Second(now);
    assertThat(createdAup.getUrl(), equalTo(aup.getUrl()));
    assertThat(createdAup.getDescription(), equalTo(aup.getDescription()));
    assertThat(createdAup.getSignatureValidityInDays(), equalTo(aup.getSignatureValidityInDays()));
    assertThat(createdAup.getCreationTime(), creationAndLastUpdateTimeMatcher);
    assertThat(createdAup.getLastUpdateTime(), creationAndLastUpdateTimeMatcher);
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCreationFailsIfAupAlreadyDefined() throws Exception {

    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.error", equalTo("AUP already exists")));
  }

  @Test
  public void aupDeletionRequiresAuthenticatedUser() throws Exception {
    mvc.perform(delete("/iam/aup")).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void aupDeletionRequiresAdminUser() throws Exception {
    mvc.perform(delete("/iam/aup")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupDeletionReturns404IfAupIsNotDefined() throws Exception {
    mvc.perform(delete("/iam/aup")).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupDeletionWorks() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    mvc.perform(delete("/iam/aup")).andExpect(status().isNoContent());

    mvc.perform(get("/iam/aup")).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateFailsWith404IfAupIsNotDefined() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());
    mvc
      .perform(MockMvcRequestBuilders.patch("/iam/aup")
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(aup)))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo(AupNotFoundError.AUP_NOT_DEFINED)));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateFailsIfAupUrlIsNotAValidUrl() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setUrl("Not-a-url");

    verifyAupUpdateFailureWithBadRequest(aup, "Invalid AUP: the AUP URL is not valid");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateFailsIfAupUrlQueryNotAllowed() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setUrl("http://aup-url.org/with?query=value");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: query string not allowed in the AUP URL");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresTextContent() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setUrl(null);

    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("Invalid AUP: the AUP URL cannot be blank")));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresSignatureValidityDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(null);

    verifyAupUpdateFailureWithBadRequest(aup, "Invalid AUP: signatureValidityInDays is required");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresPositiveSignatureValidityDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(-1L);

    verifyAupUpdateFailureWithBadRequest(aup, "Invalid AUP: signatureValidityInDays must be >= 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateFailsIfRemindersAreNotEmptyOrNullAndfSignatureValidityIsZero()
      throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(0L);

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays cannot be set if signatureValidityInDays is 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateFailsIfRemindersAreEmptyAndSignatureValidityIsNonZero() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setAupRemindersInDays("");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: non-integer value found for aupRemindersInDays");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateWorksIfRemindersAreEmptyAndSignatureValidityIsZero() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(0L);
    aup.setAupRemindersInDays("");

    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresEmptyOrNullRemindersIfSignatureValidityIsZero() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(0L);
    aup.setAupRemindersInDays("ciao");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays cannot be set if signatureValidityInDays is 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresNoLettersInAupRemindersDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setAupRemindersInDays("ciao");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: non-integer value found for aupRemindersInDays");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresNoZeroInAupRemindersDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setAupRemindersInDays("0");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: zero or negative values for reminders are not allowed");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresPositiveAupRemindersDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setAupRemindersInDays("-22");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: zero or negative values for reminders are not allowed");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresNoDuplicationInAupRemindersDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setAupRemindersInDays("30,15,15");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: duplicate values for reminders are not allowed");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresAupRemindersSmallerThanSignatureValidityDays() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(3L);
    aup.setAupRemindersInDays("4");

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays must be smaller than signatureValidityInDays");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateRequiresAupRemindersWhenSignatureValidityIsGreaterThanZero()
      throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setAupRemindersInDays(null);

    verifyAupUpdateFailureWithBadRequest(aup,
        "Invalid AUP: aupRemindersInDays must be set when signatureValidityInDays is greater than 0");
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateWorksIfRemindersAreNullAndSignatureValidityIsZero() throws Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    aup.setSignatureValidityInDays(0L);
    aup.setAupRemindersInDays(null);

    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupUpdateWorks() throws Exception {

    final String UPDATED_AUP_URL = "http://updated-aup-text.org/";
    final String UPDATED_AUP_DESC = "Updated AUP desc";

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    createAup(aup);

    String aupString = mvc.perform(get("/iam/aup"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    AupDTO savedAup = mapper.readValue(aupString, AupDTO.class);
    assertThat(savedAup.getLastUpdateTime(), new DateEqualModulo1Second(now));

    aup.setUrl(UPDATED_AUP_URL);
    aup.setDescription(UPDATED_AUP_DESC);
    aup.setSignatureValidityInDays(31L);

    // Time travel 1 minute in the future
    Date then = new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1));
    mockTimeProvider.setTime(then.getTime());

    String updatedAupString = mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    AupDTO updatedAup = mapper.readValue(updatedAupString, AupDTO.class);

    assertThat(updatedAup.getUrl(), equalTo(UPDATED_AUP_URL));
    assertThat(updatedAup.getDescription(), equalTo(UPDATED_AUP_DESC));
    assertThat(updatedAup.getCreationTime(), new DateEqualModulo1Second(now));
    assertThat(updatedAup.getLastUpdateTime(), new DateEqualModulo1Second(now));
    assertThat(updatedAup.getSignatureValidityInDays(), equalTo(31L));
  }

}
