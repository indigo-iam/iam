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

import java.util.List;
import java.util.stream.Stream;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.ProtectedResourceProperties;

/**
 * The protected resources known to IAM: IAM itself and the external resources configured under
 * <code>iam.protected-resources</code>.
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

  /**
   * All the resource identifiers, IAM first, as published in the <code>protected_resources</code>
   * authorization server metadata parameter (RFC 9728, Section 4).
   */
  public static List<String> resourceIdentifiers(IamProperties properties) {
    return Stream
      .concat(Stream.of(iamResourceIdentifier(properties)),
          properties.getProtectedResources()
            .stream()
            .map(ProtectedResourceProperties::getResource))
      .distinct()
      .toList();
  }
}
