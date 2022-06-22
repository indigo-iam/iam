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
package it.infn.mw.iam.api.scim.controller;

import it.infn.mw.iam.api.scim.provisioning.paging.DefaultScimPageRequest;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;

public class ScimControllerSupport {

  protected static final int SCIM_USER_MAX_PAGE_SIZE = 100;
  protected static final int SCIM_MEMBERS_MAX_PAGE_SIZE = 100;
  protected static final int SCIM_GROUP_MAX_PAGE_SIZE = 100;

  protected ScimPageRequest buildUserPageRequest(Integer count, Integer startIndex) {
    return buildPageRequest(count, startIndex, SCIM_USER_MAX_PAGE_SIZE);
  }

  protected ScimPageRequest buildGroupPageRequest(Integer count, Integer startIndex) {
    return buildPageRequest(count, startIndex, SCIM_GROUP_MAX_PAGE_SIZE);
  }

  protected ScimPageRequest buildPageRequest(Integer count, Integer startIndex, int maxPageSize) {

    int validCount = 0;
    int validStartIndex = 1;

    if (count == null) {
      validCount = maxPageSize;
    } else {
      validCount = count;
      if (count < 0) {
        validCount = 0;
      } else if (count > maxPageSize) {
        validCount = maxPageSize;
      }
    }

    // SCIM pages index is 1-based
    if (startIndex == null) {
      validStartIndex = 1;

    } else {

      validStartIndex = startIndex;
      if (startIndex < 1) {
        validStartIndex = 1;
      }
    }

    return new DefaultScimPageRequest.Builder().count(validCount)
      .startIndex(validStartIndex - 1)
      .build();
  }

}
