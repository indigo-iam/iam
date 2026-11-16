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

import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties;

@Component
public class DashboardUrlResolver {

  private static final String LEGACY_REQUESTS_PATH = "/dashboard#!/requests";

  private static final String REGISTRATION_REQUESTS_PATH = "/requests";
  private static final String GROUP_REQUESTS_PATH = "/requests";

  private final IamProperties properties;

  public DashboardUrlResolver(IamProperties properties) {
    this.properties = properties;
  }

  public String registrationRequestsUrl() {
    return requestsUrl(REGISTRATION_REQUESTS_PATH);
  }

  public String groupRequestsUrl() {
    return requestsUrl(GROUP_REQUESTS_PATH);
  }

  private String requestsUrl(String path) {
    String baseUrl = stripTrailingSlashes(properties.getBaseUrl());
    if (properties.getDashboard().isLegacyEnabled()) {
      return baseUrl + LEGACY_REQUESTS_PATH;
    }
    String basePath = stripTrailingSlashes(properties.getDashboard().getBasePath());
    return baseUrl + basePath + path;
  }

  private static String stripTrailingSlashes(String value) {
    int end = value.length();
    while (end > 0 && value.charAt(end - 1) == '/') {
      end--;
    }
    return value.substring(0, end);
  }
}
