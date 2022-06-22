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
package it.infn.mw.iam.api.client.search;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import org.springframework.data.domain.Sort.Direction;

import it.infn.mw.iam.api.common.form.PaginatedRequestForm;
import it.infn.mw.iam.api.scope_policy.validation.IamAccountId;
import it.infn.mw.iam.persistence.repository.client.ClientSpecs;

public class ClientSearchForm extends PaginatedRequestForm {

  private ClientSpecs.SearchType searchType = ClientSpecs.SearchType.name;

  @NotBlank(message = "Please provide a non-blank search string")
  @Size(min = 1, max = 256,
      message = "Please provide a search string that is at most 256 chars long")
  private String search;

  private Direction sortDirection = Direction.ASC;

  @Size(min = 1, max = 256, message = "Please provide a value that is between 2 and 256 chars long")
  private String sortProperties;

  boolean drOnly = false;

  @IamAccountId(nullable = true)
  private String accountId = null;

  public String getSearch() {
    return search;
  }

  public void setSearch(String search) {
    this.search = search;
  }

  public Direction getSortDirection() {
    return sortDirection;
  }

  public void setSortDirection(Direction sortDirection) {
    this.sortDirection = sortDirection;
  }

  public String getSortProperties() {
    return sortProperties;
  }

  public void setSortProperties(String sortProperties) {
    this.sortProperties = sortProperties;
  }

  public boolean isDrOnly() {
    return drOnly;
  }

  public void setDrOnly(boolean drOnly) {
    this.drOnly = drOnly;
  }

  public ClientSpecs.SearchType getSearchType() {
    return searchType;
  }

  public void setSearchType(ClientSpecs.SearchType searchType) {
    this.searchType = searchType;
  }

  public String getAccountId() {
    return accountId;
  }

  public void setAccountId(String accountId) {
    this.accountId = accountId;
  }
}
