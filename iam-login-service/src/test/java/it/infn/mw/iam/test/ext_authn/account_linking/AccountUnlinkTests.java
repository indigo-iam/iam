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
package it.infn.mw.iam.test.ext_authn.account_linking;

import static it.infn.mw.iam.authn.saml.util.Saml2Attribute.EPUID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.DEFAULT_IDP_ID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T2_EPUID;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class AccountUnlinkTests {

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private MockMvc mvc;
  
  public static final String SAML_ATTRIBUTE_ID = EPUID.getAttributeName();

  public static final String UNLINKED_ISSUER = UUID.randomUUID().toString();
  public static final String UNLINKED_SUBJECT = UUID.randomUUID().toString();

  public static final String OIDC_LINKED_ISSUER = "urn:test-oidc-issuer";
  public static final String OIDC_LINKED_SUBJECT = "test-user";

  public static final String SAML_LINKED_ISSUER = DEFAULT_IDP_ID;
  public static final String SAML_LINKED_SUBJECT = T2_EPUID;

  public static final IamSamlId UNLINKED_SAML_ID = new IamSamlId(UNLINKED_ISSUER, 
      SAML_ATTRIBUTE_ID, UNLINKED_SUBJECT);
  
  public static final IamOidcId UNLINKED_OIDC_ID = new IamOidcId(UNLINKED_ISSUER, 
      UNLINKED_SUBJECT);

  public static final IamSamlId LINKED_SAML_ID =
      new IamSamlId(SAML_LINKED_ISSUER, SAML_ATTRIBUTE_ID, SAML_LINKED_SUBJECT);

  public static final IamOidcId LINKED_OIDC_ID =
      new IamOidcId(OIDC_LINKED_ISSUER, OIDC_LINKED_SUBJECT);

  private String accountLinkingResource(ExternalAuthenticationType type) {
    return String.format("/iam/account-linking/%s", type.name());
  }

  private String accountLinkingResourceOidc() {
    return accountLinkingResource(ExternalAuthenticationType.OIDC);
  }

  private String accountLinkingResourceSaml() {
    return accountLinkingResource(ExternalAuthenticationType.SAML);
  }

  @Test
  public void accountUnlinkEndpointFailsForUnauthenticatedUsers() throws Exception {
    mvc
      .perform(delete(accountLinkingResourceOidc()).param("iss", LINKED_OIDC_ID.getIssuer())
        .param("sub", LINKED_OIDC_ID.getSubject()))
      .andDo(print())
      .andExpect(status().isUnauthorized());

    mvc
      .perform(delete(accountLinkingResourceSaml()).param("iss", LINKED_SAML_ID.getIdpId())
        .param("sub", LINKED_SAML_ID.getUserId()))
      .andDo(print())
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test")
  public void oidcAccountUnlinkSucceedsSilentlyForUnlinkedAccount() throws Throwable {

    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    Date lastUpdateTime = user.getLastUpdateTime();

    mvc
      .perform(delete(accountLinkingResourceOidc()).param("iss", UNLINKED_OIDC_ID.getIssuer())
        .param("sub", UNLINKED_OIDC_ID.getSubject())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    assertThat(user.getOidcIds(), not(containsInAnyOrder(UNLINKED_OIDC_ID)));
    assertThat(lastUpdateTime, equalTo(user.getLastUpdateTime()));
  }

  @Test
  @WithMockUser(username = "test")
  public void oidcAccountUnlinkWorks() throws Throwable {


    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    Date lastUpdateTime = user.getLastUpdateTime();

    assertThat(LINKED_OIDC_ID, is(in(user.getOidcIds())));

    mvc
      .perform(delete(accountLinkingResourceOidc()).param("iss", LINKED_OIDC_ID.getIssuer())
        .param("sub", LINKED_OIDC_ID.getSubject())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    assertThat(LINKED_OIDC_ID, not(is(in(user.getOidcIds()))));
    assertThat(user.getLastUpdateTime(), not(equalTo(lastUpdateTime)));

    // add it back, or other tests may break
    LINKED_OIDC_ID.setAccount(user);
    user.getOidcIds().add(LINKED_OIDC_ID);
    iamAccountRepo.save(user);
  }

  @Test
  @WithMockUser(username = "test")
  public void samlAccountUnlinkSucceedsSilentlyForUnlinkedAccount() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    Date lastUpdateTime = user.getLastUpdateTime();

    mvc
      .perform(delete(accountLinkingResourceSaml()).param("iss", UNLINKED_SAML_ID.getIdpId())
        .param("sub", UNLINKED_SAML_ID.getUserId())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    assertThat(UNLINKED_SAML_ID, not(is(in(user.getSamlIds()))));
    assertThat(lastUpdateTime, equalTo(user.getLastUpdateTime()));

  }

  @Test
  @WithMockUser(username = "test")
  public void samlAccountUnlinkWorks() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    assertThat(LINKED_SAML_ID, is(in(user.getSamlIds())));

    Date lastUpdateTime = user.getLastUpdateTime();

    mvc
      .perform(delete(accountLinkingResourceSaml()).param("iss", SAML_LINKED_ISSUER)
        .param("sub", SAML_LINKED_SUBJECT)
        .param("attr", LINKED_SAML_ID.getAttributeId())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    assertThat(LINKED_SAML_ID, not(is(in(user.getSamlIds()))));
    assertThat(lastUpdateTime, not(equalTo(user.getLastUpdateTime())));

    // add it back, or other tests may break
    LINKED_SAML_ID.setAccount(user);
    user.getSamlIds().add(LINKED_SAML_ID);
    iamAccountRepo.save(user);

  }
  
  

}
