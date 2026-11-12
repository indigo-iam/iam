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
package it.infn.mw.iam.test.api.account_linking;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_ERROR_KEY;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.account_linking.AccountLinkingController;
import it.infn.mw.iam.api.account_linking.AccountLinkingDisabledException;
import it.infn.mw.iam.api.account_linking.AccountLinkingService;

class AccountLinkingErrorResponseTests {

  private AccountLinkingController controller;
  private AccountLinkingService service;
  private MockMvc mvc;

  @BeforeEach
  void setup() {
    service = mock(AccountLinkingService.class);
    controller = new AccountLinkingController(service);
    ReflectionTestUtils.setField(controller, "accountLinkingEnabled", true);
    ReflectionTestUtils.setField(controller, "dashboardBasePath", "/ui");
    mvc = standaloneSetup(controller).build();
  }

  @Test
  void invalidGetCallbackRedirectsWithError() throws Exception {
    mvc.perform(get("/iam/account-linking/OIDC/done").principal(() -> "test"))
      .andExpect(status().isSeeOther())
      .andExpect(redirectedUrl("/ui"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          "No account linking done key found in request."));
  }

  @Test
  void invalidPostCallbackRedirectsWithError() throws Exception {
    mvc.perform(post("/iam/account-linking/OIDC/done").principal(() -> "test"))
      .andExpect(status().isSeeOther())
      .andExpect(redirectedUrl("/ui"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          "No account linking done key found in request."));
  }

  @Test
  void disabledBrowserLinkingRedirectsWithError() throws Exception {
    ReflectionTestUtils.setField(controller, "accountLinkingEnabled", false);
    mvc.perform(post("/iam/account-linking/OIDC"))
      .andExpect(status().isSeeOther())
      .andExpect(redirectedUrl("/ui"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          AccountLinkingDisabledException.MESSAGE));
  }

  @Test
  void legacyDashboardRedirectIsStillSupported() throws Exception {
    ReflectionTestUtils.setField(controller, "dashboardBasePath", "/dashboard");
    mvc.perform(get("/iam/account-linking/OIDC/done").principal(() -> "test"))
      .andExpect(status().isSeeOther())
      .andExpect(redirectedUrl("/dashboard"));
  }

  @Test
  void disabledExternalUnlinkReturnsForbiddenWithoutRedirect() throws Exception {
    ReflectionTestUtils.setField(controller, "accountLinkingEnabled", false);
    mvc.perform(delete("/iam/account-linking/OIDC").param("iss", "issuer").param("sub", "subject"))
      .andExpect(status().isForbidden())
      .andExpect(header().doesNotExist("Location"))
      .andExpect(jsonPath("$.error").value(AccountLinkingDisabledException.MESSAGE));
  }

  @Test
  void disabledCertificateUnlinkReturnsForbiddenWithoutRedirect() throws Exception {
    ReflectionTestUtils.setField(controller, "accountLinkingEnabled", false);
    mvc.perform(delete("/iam/account-linking/X509")
      .param("certificateSubject", "subject").param("certificateIssuer", "issuer"))
      .andExpect(status().isForbidden())
      .andExpect(header().doesNotExist("Location"))
      .andExpect(jsonPath("$.error").value(AccountLinkingDisabledException.MESSAGE));
  }

  @Test
  void invalidCertificateUnlinkReturnsBadRequestWithoutRedirect() throws Exception {
    doThrow(new IllegalArgumentException("Certificate not linked"))
      .when(service).unlinkX509Certificate(any(), anyString(), anyString());

    mvc.perform(delete("/iam/account-linking/X509").principal(() -> "test")
      .param("certificateSubject", "subject").param("certificateIssuer", "issuer"))
      .andExpect(status().isBadRequest())
      .andExpect(header().doesNotExist("Location"))
      .andExpect(jsonPath("$.error").value("Certificate not linked"));
  }

  @Test
  void successfulUnlinkStillReturnsNoContent() throws Exception {
    mvc.perform(delete("/iam/account-linking/OIDC").principal(() -> "test")
      .param("iss", "issuer").param("sub", "subject"))
      .andExpect(status().isNoContent())
      .andExpect(header().doesNotExist("Location"));
  }
}
