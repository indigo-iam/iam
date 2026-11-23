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
package it.infn.mw.iam.test.registration;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.registration.RegistrationApiController;
import it.infn.mw.iam.registration.RegistrationRequestService;

class RegistrationInsufficientAuthTests {

  private MockMvc mvc;

  @BeforeEach
  void setup() {
    mvc = controllerWithDashboardPath("/ui");
  }

  private MockMvc controllerWithDashboardPath(String path) {
    IamProperties properties = new IamProperties();
    properties.getDashboard().setBasePath(path);
    return standaloneSetup(
        new RegistrationApiController(mock(RegistrationRequestService.class), properties)).build();
  }

  private UsernamePasswordAuthenticationToken registeredUser() {
    return new UsernamePasswordAuthenticationToken("test", "N/A",
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
  }

  @Test
  void registeredUserIsRedirectedToConfiguredDashboard() throws Exception {
    mvc.perform(get("/registration/insufficient-auth").principal(registeredUser()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/ui"));
  }

  @Test
  void legacyDashboardPathIsStillSupported() throws Exception {
    controllerWithDashboardPath("/dashboard")
      .perform(get("/registration/insufficient-auth").principal(registeredUser()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"));
  }

  @Test
  void authenticatedPrincipalWithoutUserRoleSeesOriginalError() throws Exception {
    AccessDeniedException error = new AccessDeniedException("External authentication required");
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken("test", "N/A", Collections.emptyList());

    mvc
      .perform(
          get("/registration/insufficient-auth").principal(auth).requestAttr("authError", error))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/insufficient-auth"))
      .andExpect(model().attribute("authError", error));
  }

  @Test
  void missingAuthenticationDoesNotCauseNullPointerException() throws Exception {
    AccessDeniedException error = new AccessDeniedException("External authentication required");

    mvc.perform(get("/registration/insufficient-auth").requestAttr("authError", error))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/insufficient-auth"))
      .andExpect(model().attribute("authError", error));
  }

  @Test
  void unauthenticatedPrincipalDoesNotRedirectToDashboard() throws Exception {
    UsernamePasswordAuthenticationToken auth = registeredUser();
    auth.setAuthenticated(false);

    mvc.perform(get("/registration/insufficient-auth").principal(auth))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/insufficient-auth"));
  }
}
