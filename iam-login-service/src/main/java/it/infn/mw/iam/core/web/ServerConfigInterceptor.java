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
package it.infn.mw.iam.core.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import it.infn.mw.iam.config.MitreConfigurationPropertiesBean;
import it.infn.mw.iam.config.UIConfiguration;

@SuppressWarnings("deprecation")
@Component
public class ServerConfigInterceptor extends HandlerInterceptorAdapter {

  @Autowired
  private MitreConfigurationPropertiesBean config;

  @Autowired
  private UIConfiguration ui;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
      request.setAttribute("config", config);
      request.setAttribute("ui", ui);
      return true;
  }

}
