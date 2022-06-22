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
package it.infn.mw.iam.api.scim.converter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DefaultScimResourceLocationProvider implements ScimResourceLocationProvider {

  public static final String SCIM_API_ENDPOINT = "/scim";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Override
  public String userLocation(String userId) {

    return String.format("%s%s/Users/%s", baseUrl, SCIM_API_ENDPOINT, userId);
  }

  @Override
  public String groupLocation(String groupId) {

    return String.format("%s%s/Groups/%s", baseUrl, SCIM_API_ENDPOINT, groupId);
  }

}
