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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.util.Date;

import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.request.VOMSResponse;
import org.italiangrid.voms.request.impl.RESTVOMSResponseParsingStrategy;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("h2")
@AutoConfigureMockMvc
@Transactional
@TestPropertySource(properties = {"voms.aa.use-legacy-fqan-encoding=true"})
public class VomsAcLegacyEncodingTests extends TestSupport {

  RESTVOMSResponseParsingStrategy parser = new RESTVOMSResponseParsingStrategy();


  @Test
  public void fqansAreCorrectlyEncoded() throws Exception {
    IamAccount testAccount = setupTestUser();
    IamGroup rootGroup = createVomsRootGroup();
    IamGroup roleGroup = createRoleGroup(rootGroup, "VO-Admin");

    addAccountToGroup(testAccount, rootGroup);
    addAccountToGroup(testAccount, roleGroup);

    byte[] xmlResponse = mvc.perform(get("/generate-ac").headers(test0VOMSHeaders()))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    VOMSResponse response = parser.parse(new ByteArrayInputStream(xmlResponse));
    assertThat(response.hasErrors(), is(false));
    VOMSAttribute attrs = getAttributeCertificate(response);
    assertThat(attrs.getFQANs(), hasItem("/test/Role=NULL/Capability=NULL"));
    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));
  }

  @Test
  public void roleFqansAreCorrectlyEncoded() throws Exception {

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
        contains("/test/Role=VO-Admin/Capability=NULL", "/test/Role=NULL/Capability=NULL",
            "/test/sub/Role=NULL/Capability=NULL", "/test/sub/subsub/Role=NULL/Capability=NULL"));
    assertThat(attrs.getNotAfter(), lessThanOrEqualTo(Date.from(NOW_PLUS_12_HOURS)));

  }


}
