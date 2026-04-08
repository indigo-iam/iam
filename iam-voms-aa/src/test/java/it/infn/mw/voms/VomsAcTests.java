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
package it.infn.mw.voms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.request.VOMSResponse;
import org.italiangrid.voms.request.impl.RESTVOMSResponseParsingStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.voms.properties.VomsProperties;

@SpringBootTest
@ActiveProfiles("h2")
@AutoConfigureMockMvc
@Transactional
class VomsAcTests extends TestSupport {

  RESTVOMSResponseParsingStrategy parser = new RESTVOMSResponseParsingStrategy();

  @Autowired
  VomsProperties properties;

  @Autowired
  IamAupRepository aupRepo;

  @Test
  void unauthenticatedRequestGetsUnauthenticatedClientError() throws Exception {

    byte[] xmlResponse = mvc.perform(get("/generate-ac"))
      .andExpect(status().isBadRequest())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage().contains("Client is not authenticated"));
  }

  @Test
  void unregisteredUserGetsNoSuchUserError() throws Exception {
    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isForbidden())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage().contains("User unknown to this VO"));
  }

  @Test
  void registeredUserNotInVomsGroupDoesNotGetAnAC() throws Exception {

    setupTestUser();

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage().contains("User unknown to this VO"));
  }

  @Test
  void supendedUserDoesNotGetAnAc() throws Exception {

    IamAccount testAccount = setupTestUser();
    testAccount.setActive(false);
    accountRepo.save(testAccount);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage().contains("is not active"));

  }

  @Test
  void userInGroupGetsAC() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();

    addAccountToGroup(testAccount, rootGroup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertTrue(attrs.getFQANs().contains("/test"));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void userWithDifferentCertIssuerDoesNotGetAC() throws Exception {
    IamAccount testAccount = setupTestUserWithDifferentCertIssuer();
    IamGroup rootGroup = createVomsRootGroup();

    addAccountToGroup(testAccount, rootGroup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isForbidden())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage().contains("User unknown to this VO"));
  }

  @Test
  void userWithExpiredAUPDoesNotGetAc() throws Exception {

    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();

    addAccountToGroup(testAccount, rootGroup);

    IamAup aup = new IamAup();

    aup.setCreationTime(new Date());
    aup.setLastUpdateTime(new Date());
    aup.setName("default-aup");
    aup.setUrl("http://default-aup.org/");
    aup.setDescription("AUP description");
    aup.setSignatureValidityInDays(0L);
    aup.setAupRemindersInDays("30,15,1");

    aupRepo.save(aup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage()
      .contains("User test needs to sign AUP for this organization in order to proceed."));

    aupRepo.delete(aup);

    byte[] xmlResponse2 = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response2 = parser.parse(new ByteArrayInputStream(xmlResponse2));
    assertFalse(response2.hasErrors());
  }


  @Test
  void allGroupsAreReturnedForUser() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup subSubGroup = createChildGroup(subGroup, "subsub");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, subSubGroup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(3, attrs.getFQANs().size());
    assertTrue(attrs.getFQANs().contains("/test"));
    assertTrue(attrs.getFQANs().contains("/test/sub"));
    assertTrue(attrs.getFQANs().contains("/test/sub/subsub"));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void optionalGroupIsNotReturnedForUser() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup optionalGroup = createOptionalGroup(subGroup, "optional");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, optionalGroup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(2, attrs.getFQANs().size());
    assertTrue(attrs.getFQANs().contains("/test"));
    assertTrue(attrs.getFQANs().contains("/test/sub"));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void optionalGroupIsReturnedForUserIfRequested() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup optionalGroup = createOptionalGroup(subGroup, "optional");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, optionalGroup);

    byte[] xmlResponse = mvc
      .perform(get("/generate-ac").headers(test0VOMSHeaders()).param("fqans", "/test/sub/optional"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(3, attrs.getFQANs().size());
    assertTrue(attrs.getFQANs().contains("/test"));
    assertTrue(attrs.getFQANs().contains("/test/sub"));
    assertTrue(attrs.getFQANs().contains("/test/sub/optional"));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void requestedFqanOrderEnforced() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup subSubGroup = createChildGroup(subGroup, "subsub");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, subSubGroup);

    byte[] xmlResponse = mvc
      .perform(get("/generate-ac").headers(test0VOMSHeaders())
        .param("fqans", "/test/sub,/test/sub/subsub"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(3, attrs.getFQANs().size());
    assertTrue(attrs.getFQANs().containsAll(List.of("/test/sub", "/test/sub/subsub", "/test")));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void roleRequestWorks() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup subSubGroup = createChildGroup(subGroup, "subsub");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, subSubGroup);

    byte[] xmlResponse = mvc
      .perform(
          get("/generate-ac").headers(test0VOMSHeaders()).param("fqans", "/test/Role=VO-Admin"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(4, attrs.getFQANs().size());
    assertTrue(attrs.getFQANs()
      .containsAll(List.of("/test/Role=VO-Admin", "/test", "/test/sub", "/test/sub/subsub")));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void roleRequestInAnOptionalGroupWorks() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup optionalGroup = createOptionalGroup(rootGroup, "optional");
    IamGroup roleGroup = createRoleGroup(optionalGroup, "VO-Admin");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, optionalGroup);
    addAccountToGroup(testAccount, roleGroup);

    byte[] xmlResponse = mvc
      .perform(get("/generate-ac").headers(test0VOMSHeaders())
        .param("fqans", "/test/optional/Role=VO-Admin"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(2, attrs.getFQANs().size());
    assertTrue(attrs.getFQANs().containsAll(List.of("/test/optional/Role=VO-Admin", "/test")));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void roleRequestForUnassignedRoleIsHandledCorrectly() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);

    byte[] xmlResponse = mvc
      .perform(
          get("/generate-ac").headers(test0VOMSHeaders()).param("fqans", "/test/Role=production"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage()
      .contains("User is not authorized to request attribute"));
  }

  @Test
  void gasAreCorrectlyEncoded() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    addAccountToGroup(testAccount, rootGroup);
    assignGenericAttribute(testAccount, TEST_ATTRIBUTE);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));

    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(1, attrs.getGenericAttributes().size());
    assertEquals("test", attrs.getGenericAttributes().get(0).getName());
    assertEquals("test", attrs.getGenericAttributes().get(0).getValue());
    assertEquals(properties.getAa().getVoName(), attrs.getGenericAttributes().get(0).getContext());
  }

  @Test
  void acLifetimeIsCorrectlyEnforced() throws Exception {

    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    addAccountToGroup(testAccount, rootGroup);

    final long sevenDaysInSeconds = TimeUnit.DAYS.toSeconds(7);

    byte[] xmlResponse = mvc
      .perform(get("/generate-ac").param("lifetime", String.valueOf(sevenDaysInSeconds))
        .headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    VOMSAttribute attrs = getAttributeCertificate(response);

    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);

    final long oneHourInSeconds = TimeUnit.HOURS.toSeconds(1);
    xmlResponse = mvc
      .perform(get("/generate-ac").param("lifetime", String.valueOf(oneHourInSeconds))
        .headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    response = parser.parse(new ByteArrayInputStream(xmlResponse));
    attrs = getAttributeCertificate(response);

    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_1_HOUR)) > 0);
  }

  @Test
  void lifetimeValidationWorks() throws Exception {

    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    addAccountToGroup(testAccount, rootGroup);

    byte[] xmlResponse =
        mvc.perform(get("/generate-ac").param("lifetime", "-100").headers(test0VOMSHeaders()))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertTrue(response.hasErrors());
    assertEquals(1, response.errorMessages().length);
    assertEquals("lifetime must be a positive integer", response.errorMessages()[0].getMessage());

    xmlResponse =
        mvc.perform(get("/generate-ac").param("lifetime", "pippo").headers(test0VOMSHeaders()))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsByteArray();

    response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertTrue(response.hasErrors());
    assertEquals(1, response.errorMessages().length);
    assertTrue(
        response.errorMessages()[0].getMessage().contains("Failed to convert property value"));
  }

  @Test
  void allDescendantsFromRootGroupAreReturnedForUser() throws Exception {

    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup subSubGroup = createChildGroup(subGroup, "subsub");
    IamGroup anotherRoot = createGroup("another");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, subSubGroup);
    addAccountToGroup(testAccount, anotherRoot);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertFalse(response.hasErrors());
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertEquals(3, attrs.getFQANs().size());
    assertFalse(attrs.getFQANs().contains("/another"));
    assertTrue(attrs.getFQANs().contains("/test"));
    assertTrue(attrs.getFQANs().contains("/test/sub"));
    assertTrue(attrs.getFQANs().contains("/test/sub/subsub"));
    assertFalse(attrs.getNotAfter().compareTo(Date.from(NOW_PLUS_12_HOURS)) > 0);
  }

  @Test
  void groupNotDescendantsFromRootCannotBeReturnedForUser() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");
    IamGroup subGroup = createChildGroup(rootGroup, "sub");
    IamGroup subSubGroup = createChildGroup(subGroup, "subsub");
    IamGroup anotherRoot = createGroup("another");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);
    addAccountToGroup(testAccount, subGroup);
    addAccountToGroup(testAccount, subSubGroup);
    addAccountToGroup(testAccount, anotherRoot);

    byte[] xmlResponse =
        mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()).param("fqans", "/another"))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertTrue(response.hasErrors());
    assertTrue(response.errorMessages()[0].getMessage()
      .contains("User is not authorized to request attribute"));
  }
}
