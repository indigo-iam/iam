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
package it.infn.mw.iam.test.core;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.core.web.IamRootController;

class IamRootDashboardRedirectTests {

  private MockMvc mvc;

  @BeforeEach
  void setup() {
    IamRootController controller = new IamRootController();
    ReflectionTestUtils.setField(controller, "dashboardBasePath", "/ui");
    mvc = standaloneSetup(controller).build();
  }

  @Test
  void anonymousVisitorGoesDirectlyToConfiguredDashboard() throws Exception {
    mvc.perform(get("/")).andExpect(status().isFound()).andExpect(redirectedUrl("/ui"));
  }

  @Test
  void anonymousTokenAlsoGoesToConfiguredDashboard() throws Exception {
    AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken("key", "anonymousUser",
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
    mvc.perform(get("/").principal(auth))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/ui"));
  }

  @Test
  void authenticatedVisitorGoesToConfiguredDashboard() throws Exception {
    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("test",
        "N/A", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    mvc.perform(get("/").principal(auth))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/ui"));
  }

  @Test
  void homeAliasesUseConfiguredDashboard() throws Exception {
    for (String path : new String[] {"/home", "/index"}) {
      mvc.perform(get(path)).andExpect(status().isFound()).andExpect(redirectedUrl("/ui"));
    }
  }

  @Test
  void unregisteredExternalUserContinuesRegistration() throws Exception {
    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("external",
        "N/A", Collections.singletonList(EXT_AUTHN_UNREGISTERED_USER_AUTH));
    mvc.perform(get("/").principal(auth))
      .andExpect(status().isOk())
      .andExpect(forwardedUrl("/start-registration"));
  }

  @Test
  void loginPageRemainsAvailableToStartAuthorizationFlow() throws Exception {
    mvc.perform(get("/login")).andExpect(status().isOk()).andExpect(view().name("iam/login"));
  }
}
