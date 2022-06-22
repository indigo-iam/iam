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
package it.infn.mw.iam.api.common.form;

import javax.validation.constraints.Size;

import it.infn.mw.iam.api.common.validator.NullableNonBlankString;

public class PaginatedRequestWithFilterForm extends PaginatedRequestForm {

  @NullableNonBlankString(message = "Please provide a non-blank filter string")
  @Size(min = 2, max = 64, message = "Please provide a filter that is between 2 and 64 chars long")
  private String filter;

  public String getFilter() {
    return filter;
  }

  public void setFilter(String filter) {
    this.filter = filter;
  }

}
