/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import it.infn.mw.iam.config.saml.IamSamlProperties;
import it.infn.mw.iam.core.IamProperties;

@Component
public class IamViewInfoInterceptor extends HandlerInterceptorAdapter {

  public static final String LOGIN_PAGE_CONFIGURATION_KEY = "loginPageConfiguration";
  public static final String IAM_PROPERTIES_KEY = "iamProperties";
  public static final String IAM_SAML_PROPERTIES_KEY = "iamSamlProperties";
  public static final String IAM_OIDC_PROPERTIES_KEY = "iamOidcProperties";

  @Value("${iam.version}")
  String iamVersion;

  @Value("${git.commit.id.abbrev}")
  String gitCommitId;

  @Autowired
  LoginPageConfiguration loginPageConfiguration;

  @Autowired
  IamProperties properties;

  @Autowired
  IamSamlProperties samlProperties;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {

    request.setAttribute("iamVersion", iamVersion);
    request.setAttribute("gitCommitId", gitCommitId);

    request.setAttribute(LOGIN_PAGE_CONFIGURATION_KEY, loginPageConfiguration);
    request.setAttribute(IAM_PROPERTIES_KEY, properties);
    request.setAttribute(IAM_SAML_PROPERTIES_KEY, samlProperties);

    return true;
  }

}
