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
package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class TokensListResponse<T> {

  private long totalResults;
  private long itemsPerPage;
  private long startIndex;
  private List<T> resources = new ArrayList<>();

  public TokensListResponse() {}

  public TokensListResponse(List<T> resources, long totalResults, long itemsPerPage,
      long startIndex) {

    this.resources = resources;
    this.totalResults = totalResults;
    this.itemsPerPage = itemsPerPage;
    this.startIndex = startIndex;
  }

  public long getTotalResults() {

    return totalResults;
  }

  public long getItemsPerPage() {

    return itemsPerPage;
  }

  public long getStartIndex() {

    return startIndex;
  }

  @JsonProperty("Resources")
  public List<T> getResources() {

    return resources;
  }
}
