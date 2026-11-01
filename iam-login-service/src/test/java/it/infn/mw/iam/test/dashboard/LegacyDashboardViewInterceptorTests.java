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
package it.infn.mw.iam.test.dashboard;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.web.IamRootController;
import it.infn.mw.iam.core.web.registration.DefaultStartRegistrationController;
import it.infn.mw.iam.dashboard.DashboardController;
import it.infn.mw.iam.dashboard.LegacyDashboardViewInterceptor;

class LegacyDashboardViewInterceptorTests {

  private final IamProperties properties = new IamProperties();
  private final LegacyDashboardViewInterceptor interceptor =
      new LegacyDashboardViewInterceptor(properties);

  private void intercept(ModelAndView mav) {
    interceptor.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(),
        new Object(), mav);
  }

  @ParameterizedTest
  @ValueSource(strings = {"home", "manage", "iam/dashboard"})
  void enabledByDefault(String name) {
    ModelAndView mav = new ModelAndView(name);
    intercept(mav);
    assertThat(mav.getViewName(), is(name));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/", "/home", "/index", "/manage", "/manage/clients",
      "/dashboard", "/start-registration"})
  void disablesAllLegacyEntrypoints(String path) throws Exception {
    properties.getDashboard().setLegacyEnabled(false);
    MockMvc mvc = MockMvcBuilders.standaloneSetup(new IamRootController(),
        new DashboardController(), new DefaultStartRegistrationController(new MockEnvironment()))
      .addInterceptors(interceptor)
      .build();
    mvc.perform(get(path).principal(new TestingAuthenticationToken("user", "unused", "ROLE_USER")))
      .andExpect(view().name("iam/legacyDashboardDisabled"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"iam/login", "iam/register", "iam/registrationDisabled",
      "iam/expiredsession", "redirect:/login", "forward:/start-registration"})
  void preservesOtherViews(String name) {
    properties.getDashboard().setLegacyEnabled(false);
    ModelAndView mav = new ModelAndView(name);
    intercept(mav);
    assertThat(mav.getViewName(), is(name));
  }

  @Test
  void preservesAnonymousLoginAndRegistration() throws Exception {
    properties.getDashboard().setLegacyEnabled(false);
    MockEnvironment environment = new MockEnvironment();
    environment.setActiveProfiles("registration");
    MockMvc mvc = MockMvcBuilders.standaloneSetup(new IamRootController(),
        new DefaultStartRegistrationController(environment))
      .addInterceptors(interceptor)
      .build();
    mvc.perform(get("/login")).andExpect(view().name("iam/login"));
    mvc.perform(get("/")).andExpect(view().name("redirect:/login"));
    mvc.perform(get("/start-registration")).andExpect(view().name("iam/register"));
  }

  @Test
  void preservesResponsesWithoutAView() {
    properties.getDashboard().setLegacyEnabled(false);
    intercept(null);
    ModelAndView mav = new ModelAndView();
    intercept(mav);
    assertThat(mav.isEmpty(), is(true));
  }

  @Test
  void newDashboardFlagDoesNotDisableLegacyViews() {
    properties.getDashboard().setEnabled(true);
    ModelAndView mav = new ModelAndView("iam/dashboard");
    intercept(mav);
    assertThat(mav.getViewName(), is("iam/dashboard"));
  }

  @Test
  void linkRequiresNewDashboardConfiguration() {
    properties.getDashboard().setLegacyEnabled(false);
    ModelAndView mav = new ModelAndView("iam/dashboard");
    intercept(mav);
    assertThat(mav.getModel().get("newDashboardEnabled"), is(false));
    properties.getDashboard().setEnabled(true);
    mav = new ModelAndView("iam/dashboard");
    intercept(mav);
    assertThat(mav.getModel().get("newDashboardEnabled"), is(true));
  }
}
