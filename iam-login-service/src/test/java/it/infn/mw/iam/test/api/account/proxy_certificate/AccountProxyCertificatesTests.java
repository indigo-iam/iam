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
package it.infn.mw.iam.test.api.account.proxy_certificate;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import it.infn.mw.iam.api.proxy.ProxyCertificateDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class AccountProxyCertificatesTests extends X509TestSupport {

  public static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  public static final ResultMatcher BAD_REQUEST = status().isBadRequest();

  public static final String ACCOUNT_PROXY_CERT_ENDPOINT = "/iam/account/me/proxycert";

  public static final String TEST_USER = "test";
  public static final String TEST_100_USER = "test_100";

  public static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";
  public static final String ACCOUNT_NOT_FOUND = "Account not found";

  @Autowired
  private IamAccountRepository repo;

  @Autowired
  private ProxyHelperService proxyHelper;

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
  public void addingProxyRequiresAuthenticatedUser() throws Exception {

    mvc.perform(put(ACCOUNT_PROXY_CERT_ENDPOINT)).andExpect(UNAUTHORIZED);

  }

  @Test
  @WithMockUser("test")
  public void addingProxyRequiresProxyCert() throws Exception {

    ProxyCertificateDTO dto = new ProxyCertificateDTO();

    mvc
      .perform(put(ACCOUNT_PROXY_CERT_ENDPOINT).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("Invalid proxy")));

  }

  @Test
  @WithMockUser("test")
  public void addingProxyRequiresOwnedCertificate() throws Exception {

    ProxyCertificate pc = proxyHelper.generateProxy(TEST_0_PEM_CREDENTIAL, 300);
    String pcPem = proxyHelper.proxyCertificateToPemString(pc);

    ProxyCertificateDTO dto = new ProxyCertificateDTO();
    dto.setCertificateChain(pcPem);

    mvc
      .perform(put(ACCOUNT_PROXY_CERT_ENDPOINT).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("does not own")));
  }

  @Test
  @WithMockUser("test")
  public void addingProxyDoesNotWorkForPlainX509Certificate() throws Exception {

    ProxyCertificateDTO dto = new ProxyCertificateDTO();
    dto.setCertificateChain(TEST_0_CERT_STRING);

    mvc
      .perform(put(ACCOUNT_PROXY_CERT_ENDPOINT).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("Error reading proxy certificate")));
  }

  @Test
  @WithMockUser("test")
  public void addingJunkFailsNicely() throws Exception {

    ProxyCertificateDTO dto = new ProxyCertificateDTO();
    dto.setCertificateChain("JunkJunk");

    mvc
      .perform(put(ACCOUNT_PROXY_CERT_ENDPOINT).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("Error reading proxy certificate")));
  }

  @Test
  @WithMockUser("test")
  public void addingProxyWorks() throws Exception {

    IamAccount account =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    linkTest0CertificateToAccount(account);

    repo.save(account);

    ProxyCertificate pc = proxyHelper.generateProxy(TEST_0_PEM_CREDENTIAL, 300);
    String pcPem = proxyHelper.proxyCertificateToPemString(pc);

    ProxyCertificateDTO dto = new ProxyCertificateDTO();
    dto.setCertificateChain(pcPem);

    mvc
      .perform(put(ACCOUNT_PROXY_CERT_ENDPOINT).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isOk());

    account = repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    assertThat(account.getX509Certificates().stream().anyMatch(c -> c.getProxy() != null),
        is(true));
  }


}
