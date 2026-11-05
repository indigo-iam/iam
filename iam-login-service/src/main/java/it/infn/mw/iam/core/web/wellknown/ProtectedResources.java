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
package it.infn.mw.iam.core.web.wellknown;

import it.infn.mw.iam.config.IamProperties;

/**
 * IAM's own protected resource. The external ones are held by {@link ProtectedResourceRegistry}.
 */
public final class ProtectedResources {

  public static final String PROTECTED_RESOURCE_URL = ".well-known/oauth-protected-resource";

  private ProtectedResources() {}

  /**
   * The resource identifier of the APIs IAM itself protects: the IAM base URL, without a
   * terminating slash.
   */
  public static String iamResourceIdentifier(IamProperties properties) {
    String baseUrl = properties.getBaseUrl();
    return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
  }

  public static String iamMetadataUrl(IamProperties properties) {
    return String.format("%s/%s", iamResourceIdentifier(properties), PROTECTED_RESOURCE_URL);
  }
}
