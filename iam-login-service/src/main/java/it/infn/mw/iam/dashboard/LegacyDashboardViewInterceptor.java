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
package it.infn.mw.iam.dashboard;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.config.IamProperties;

@Component
public class LegacyDashboardViewInterceptor implements HandlerInterceptor {

  private static final Set<String> LEGACY_VIEWS = Set.of("home", "manage", "iam/dashboard");

  private final IamProperties properties;

  public LegacyDashboardViewInterceptor(IamProperties properties) {
    this.properties = properties;
  }

  @Override
  public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
      ModelAndView modelAndView) {
    if (properties.getDashboard().isLegacyEnabled() || modelAndView == null
        || modelAndView.getViewName() == null
        || !LEGACY_VIEWS.contains(modelAndView.getViewName())) {
      return;
    }

    modelAndView.setViewName("iam/legacyDashboardDisabled");
    modelAndView.addObject("newDashboardEnabled", properties.getDashboard().isEnabled());
  }
}
