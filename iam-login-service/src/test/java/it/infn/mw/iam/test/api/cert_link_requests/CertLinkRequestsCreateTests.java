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

import static java.lang.String.format;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.notification.service.NotificationStoreService;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK, properties = {
    "x509.trustAnchorsDir=src/test/resources/test-ca" })
public class CertLinkRequestsCreateTests extends CertLinkRequestsTestUtils {

  private final static String CREATE_URL = "/iam/cert_link_requests";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private NotificationStoreService notificationService;

  @Autowired
  private IamEmailNotificationRepository emailRepository;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    notificationService.clearAllNotifications();
  }

  @Test
  @WithMockUser(roles = { "ADMIN" }, username = TEST_ADMIN)
  public void createCertLinkRequestAsAdmin() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.username", equalTo(TEST_ADMIN)))
      .andExpect(jsonPath("$.userUuid", equalTo(TEST_ADMIN_UUID)))
      .andExpect(jsonPath("$.userFullName", equalTo(TEST_ADMIN_FULL_NAME)))
      .andExpect(jsonPath("$.subjectDn", equalTo(TEST_SUBJECTDN_OK)))
      .andExpect(jsonPath("$.issuerDn", equalTo(TEST_ISSUERDN_OK)))
      .andExpect(jsonPath("$.status", equalTo(IamRequestStatus.PENDING.name())));
    // @formatter:on
    int mailCount = notificationService.countPendingNotifications();
    assertThat(mailCount, equalTo(1));

    List<IamEmailNotification> mails = emailRepository.findByNotificationType(IamNotificationType.CERTIFICATE_LINK);
    assertThat(mails, hasSize(1));
    assertThat(mails.get(0).getBody(), containsString(format("Username: %s", TEST_ADMIN)));
    assertThat(mails.get(0).getBody(), containsString(TEST_SUBJECTDN_OK));
    assertThat(mails.get(0).getBody(), containsString(request.getNotes()));
    assertThat(mails.get(0).getBody(), containsString(baseUrl));
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestAsUser() throws Exception {

    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.subjectDn", equalTo(TEST_SUBJECTDN_OK)))
      .andExpect(jsonPath("$.issuerDn", equalTo(TEST_ISSUERDN_OK)))
      .andExpect(jsonPath("$.status", equalTo(IamRequestStatus.PENDING.name())));
    // @formatter:on
    int mailCount = notificationService.countPendingNotifications();
    assertThat(mailCount, equalTo(1));

    List<IamEmailNotification> mails = emailRepository.findByNotificationType(IamNotificationType.CERTIFICATE_LINK);
    assertThat(mails, hasSize(1));
    assertThat(mails.get(0).getBody(), containsString(format("Username: %s", TEST_100_USERNAME)));
    assertThat(mails.get(0).getBody(), containsString(TEST_SUBJECTDN_OK));
    assertThat(mails.get(0).getBody(), containsString(request.getNotes()));
    assertThat(mails.get(0).getBody(), containsString(baseUrl));
  }

  @Test
  @WithAnonymousUser
  public void createCertLinkRequestAsAnonymous() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestWitInvalidLabel() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest(null, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on

    request.setLabel("");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestWithInvalidSubject() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", "", TEST_ISSUERDN_OK, null);
    String body = mapper.writeValueAsString(request);
    JSONObject jsonBody = new JSONObject(body);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(body))
      .andExpect(status().isBadRequest());
    // @formatter:on

    jsonBody.put("subjectDn", "non valid dn");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(jsonBody.toString()))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestWithInvalidIssuer() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, "", null);
    String body = mapper.writeValueAsString(request);
    JSONObject jsonBody = new JSONObject(body);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(body))
      .andExpect(status().isBadRequest());
    // @formatter:on

    jsonBody.put("issuerDn", "non valid dn");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(jsonBody.toString()))
      .andExpect(status().isBadRequest());
    // @formatter:on

    jsonBody.put("issuerDn", "CN=Well Formatted, O=But Unknown, C=ca");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(jsonBody.toString()))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestWithPem() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", null, null, TEST0_PEM_STRING);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.subjectDn", equalTo("CN=test0,O=IGI,C=IT")))
      .andExpect(jsonPath("$.issuerDn", equalTo("CN=Test CA,O=IGI,C=IT")))
      .andExpect(jsonPath("$.status", equalTo(IamRequestStatus.PENDING.name())));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestWithInvalidPem() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, "invalid pem");

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestWithInconsistentSubjectAndPem() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", "CN=Inconsistent,O=IGI,C=IT", TEST_ISSUERDN_OK, TEST0_PEM_STRING);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestAlreadyExists() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    savePendingCertLinkRequest(TEST_100_USERNAME, TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("already exist")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestUserAlreadyLinked() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    linkAccountToCert(TEST_100_USERNAME, request);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
      .contentType(MediaType.APPLICATION_JSON)
      .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("already linked")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestLinkekToSomeoneElse() throws Exception {
    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);

    linkAccountToCert(TEST_101_USERNAME, request);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
      .contentType(MediaType.APPLICATION_JSON)
      .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("already linked to another user")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = { "ADMIN", "USER" }, username = TEST_100_USERNAME)
  public void createCertLinkRequestAsUserWithBothRoles() throws Exception {

    CertLinkRequestDTO request = buildCertLinkRequest("mylabel", TEST_SUBJECTDN_OK, TEST_ISSUERDN_OK, null);
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.subjectDn", equalTo(TEST_SUBJECTDN_OK)))
      .andExpect(jsonPath("$.issuerDn", equalTo(TEST_ISSUERDN_OK)))
      .andExpect(jsonPath("$.status", equalTo(IamRequestStatus.PENDING.name())));
    // @formatter:on
  }
}
