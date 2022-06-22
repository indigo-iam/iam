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
package it.infn.mw.iam.core.web.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.saml.IamSamlProperties;
import it.infn.mw.iam.core.web.loginpage.LoginPageConfiguration;
import it.infn.mw.iam.rcauth.RCAuthProperties;

@Component
public class IamViewInfoInterceptor implements HandlerInterceptor {

  public static final String LOGIN_PAGE_CONFIGURATION_KEY = "loginPageConfiguration";
  public static final String ORGANISATION_NAME_KEY = "iamOrganisationName";
  public static final String IAM_SAML_PROPERTIES_KEY = "iamSamlProperties";
  public static final String IAM_OIDC_PROPERTIES_KEY = "iamOidcProperties";
  public static final String IAM_VERSION_KEY = "iamVersion";
  public static final String GIT_COMMIT_ID_KEY = "gitCommitId";
  public static final String SIMULATE_NETWORK_LATENCY_KEY = "simulateNetworkLatency";
  public static final String RCAUTH_ENABLED_KEY = "iamRcauthEnabled";

  public static final String RESOURCES_PATH_KEY = "resourcesPrefix";

  @Value("${iam.version}")
  String iamVersion;

  @Value("${git.commit.id.abbrev}")
  String gitCommitId;

  @Value("${iam.organisation.name}")
  String organisationName;
  
  @Autowired
  LoginPageConfiguration loginPageConfiguration;

  @Autowired
  IamSamlProperties samlProperties;
  
  @Autowired
  RCAuthProperties rcAuthProperties;

  @Autowired
  IamProperties iamProperties;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    
    request.setAttribute(IAM_VERSION_KEY, iamVersion);
    request.setAttribute(GIT_COMMIT_ID_KEY, gitCommitId);

    request.setAttribute(ORGANISATION_NAME_KEY, organisationName);
    
    request.setAttribute(LOGIN_PAGE_CONFIGURATION_KEY, loginPageConfiguration);
    
    request.setAttribute(IAM_SAML_PROPERTIES_KEY, samlProperties);
    
    request.setAttribute(RCAUTH_ENABLED_KEY, rcAuthProperties.isEnabled());
    

    if (iamProperties.getVersionedStaticResources().isEnableVersioning()) {
      request.setAttribute(RESOURCES_PATH_KEY, String.format("/resources/%s", gitCommitId));
    } else {
      request.setAttribute(RESOURCES_PATH_KEY, "/resources");
    }

    return true;
  }

}
