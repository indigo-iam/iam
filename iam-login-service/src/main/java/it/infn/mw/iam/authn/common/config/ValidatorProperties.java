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
package it.infn.mw.iam.authn.common.config;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.String.format;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.validation.constraints.NotBlank;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class ValidatorProperties {

  @NotBlank
  private String kind;

  private Map<String, String> params = Maps.newHashMap();

  private List<ValidatorProperties> childrens = Lists.newArrayList();

  public String getKind() {
    return kind;
  }

  public void setKind(String kind) {
    this.kind = kind;
  }


  public Map<String, String> getParams() {
    return params;
  }


  public void setParams(Map<String, String> params) {
    this.params = params;
  }


  public List<ValidatorProperties> getChildrens() {
    return childrens;
  }


  public void setChildrens(List<ValidatorProperties> childrens) {
    this.childrens = childrens;
  }

  public String getRequiredNonEmptyParam(String paramName) {
    checkArgument(nonNull(getParams()), "params required");
    checkArgument(!isNullOrEmpty(getParams().get(paramName)), format("%s param required", paramName));
    return getParams().get(paramName);
  }

  public String getOptionalParam(String paramName) {
    if (Objects.isNull(getParams())) {
      return null;
    }
    return getParams().get(paramName);
  }
  
  public void requireChildren() {
    if (isNull(getChildrens()) || getChildrens().isEmpty()) {
      throw new ValidatorConfigError("children validators required");
    }
  }

}
