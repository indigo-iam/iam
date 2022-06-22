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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.request.VOMSResponse;
import org.italiangrid.voms.request.impl.RESTVOMSResponseParsingStrategy;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.voms.properties.VomsProperties;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("h2")
@AutoConfigureMockMvc
@Transactional
public class VomsAcTests extends TestSupport {

  RESTVOMSResponseParsingStrategy parser = new RESTVOMSResponseParsingStrategy();

  @Autowired
  VomsProperties properties;


  @Test
  public void unauthenticatedRequestGetsUnauthenticatedClientError() throws Exception {

    byte[] xmlResponse = mvc.perform(get("/generate-ac"))
      .andExpect(status().isBadRequest())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertThat(response.hasErrors(), is(true));
    assertThat(response.errorMessages()[0].getMessage(),
        containsString("Client is not authenticated"));
  }

  @Test
  public void unregisteredUserGetsNoSuchUserError() throws Exception {
    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isForbidden())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertThat(response.hasErrors(), is(true));
    assertThat(response.errorMessages()[0].getMessage(), containsString("User unknown to this VO"));
  }

  @Test
  public void registeredUserNotInVomsGroupDoesNotGetAnAC() throws Exception {

    setupTestUser();

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertThat(response.hasErrors(), is(true));
    assertThat(response.errorMessages()[0].getMessage(), containsString("User unknown to this VO"));
  }

  @Test
  public void supendedUserDoesNotGetsAnAc() throws Exception {

    IamAccount testAccount = setupTestUser();
    testAccount.setActive(false);
    accountRepo.save(testAccount);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertThat(response.hasErrors(), is(true));

    assertThat(response.errorMessages()[0].getMessage(), containsString("is not active"));

  }

  @Test
  public void userInGroupGetsAC() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();

    addAccountToGroup(testAccount, rootGroup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertThat(response.hasErrors(), is(false));
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertThat(attrs.getFQANs(), hasItem("/test"));
    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));
  }


  @Test
  public void allGroupsAreReturnedForUser() throws Exception {
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
    assertThat(response.hasErrors(), is(false));
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertThat(attrs.getFQANs(), hasSize(3));
    assertThat(attrs.getFQANs(), hasItem("/test"));
    assertThat(attrs.getFQANs(), hasItem("/test/sub"));
    assertThat(attrs.getFQANs(), hasItem("/test/sub/subsub"));
    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));
  }


  @Test
  public void requestedFqanOrderEnforced() throws Exception {
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
    assertThat(response.hasErrors(), is(false));
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertThat(attrs.getFQANs(), hasSize(3));
    assertThat(attrs.getFQANs(), contains("/test/sub", "/test/sub/subsub", "/test"));
    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));
  }

  @Test
  public void roleRequestWorks() throws Exception {
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
    assertThat(response.hasErrors(), is(false));
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertThat(attrs.getFQANs(), hasSize(4));
    assertThat(attrs.getFQANs(),
        contains("/test/Role=VO-Admin", "/test", "/test/sub", "/test/sub/subsub"));
    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));

  }

  @Test
  public void roleRequestForUnassignedRoleIsHandledCorrectly() throws Exception {
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
    assertThat(response.hasErrors(), is(true));
    assertThat(response.errorMessages()[0].getMessage(),
        containsString("User is not authorized to request attribute"));
  }

  @Test
  public void gasAreCorrectlyEncoded() throws Exception {
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
    assertThat(attrs.getGenericAttributes(), hasSize(1));
    assertThat(attrs.getGenericAttributes().get(0).getName(), is("test"));
    assertThat(attrs.getGenericAttributes().get(0).getValue(), is("test"));
    assertThat(attrs.getGenericAttributes().get(0).getContext(),
        is(properties.getAa().getVoName()));

  }

  @Test
  public void acLifetimeIsCorrectlyEnforced() throws Exception {

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

    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));

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

    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_1_HOUR)));
  }

  @Test
  public void lifetimeValidationWorks() throws Exception {

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

    assertThat(response.hasErrors(), is(true));
    assertThat(response.errorMessages(), arrayWithSize(1));
    assertThat(response.errorMessages()[0].getMessage(), is("lifetime must be a positive integer"));

    xmlResponse =
        mvc.perform(get("/generate-ac").param("lifetime", "pippo").headers(test0VOMSHeaders()))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsByteArray();

    response = parser.parse(new ByteArrayInputStream(xmlResponse));

    assertThat(response.hasErrors(), is(true));
    assertThat(response.errorMessages(), arrayWithSize(1));
    assertThat(response.errorMessages()[0].getMessage(),
        containsString("Failed to convert property value"));
  }
}
