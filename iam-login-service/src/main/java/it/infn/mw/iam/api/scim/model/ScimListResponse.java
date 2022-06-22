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
package it.infn.mw.iam.api.scim.model;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import it.infn.mw.iam.api.common.ListResponseDTO;

public class ScimListResponse<T> extends ListResponseDTO<T> {

  public static final String SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

  private final Set<String> schemas = new HashSet<>(Collections.singletonList(SCHEMA));

  public ScimListResponse(long totalResults, int itemsPerPage, int startIndex, List<T> resources) {
    super(totalResults, itemsPerPage, startIndex, resources);
  }

  private ScimListResponse(ScimListResponseBuilder<T> builder) {
    super(builder);
  }

  public Set<String> getSchemas() {

    return schemas;
  }

  public static <T> ScimListResponseBuilder<T> builder() {
    return new ScimListResponseBuilder<>();
  }


  public static class ScimListResponseBuilder<T> extends ListResponseDTO.Builder<T> {

    @Override
    public ScimListResponse<T> build() {

      return new ScimListResponse<>(this);
    }
  }
}
