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
package it.infn.mw.iam.config;

import java.util.EnumSet;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import javax.validation.constraints.NotBlank;

import com.google.common.collect.Lists;

import it.infn.mw.iam.config.scim.ScimProperties.LabelDescriptor;

public class IamTokenEnhancerProperties {

  // To be expanded in the future to include also
  // access_token and userinfo endpoint responses
  public enum TokenContext {
    ID_TOKEN
  }

  public static class IncludeLabelProperties {

    @NotNull
    private LabelDescriptor label;

    @Size(min = 1, message = "At least one context must be provided")
    private EnumSet<TokenContext> context =
        EnumSet.of(TokenContext.ID_TOKEN);

    @NotBlank(message = "Please provide a claim name (in snake_case)")
    private String claimName;

    public LabelDescriptor getLabel() {
      return label;
    }

    public void setLabel(LabelDescriptor label) {
      this.label = label;
    }

    public EnumSet<TokenContext> getContext() {
      return context;
    }

    public void setContext(EnumSet<TokenContext> context) {
      this.context = context;
    }

    public String getClaimName() {
      return claimName;
    }

    public void setClaimName(String claimName) {
      this.claimName = claimName;
    }
  }

  @Valid
  List<IncludeLabelProperties> includeLabels = Lists.newArrayList();

  public List<IncludeLabelProperties> getIncludeLabels() {
    return includeLabels;
  }

  public void setIncludeLabels(List<IncludeLabelProperties> includeLabels) {
    this.includeLabels = includeLabels;
  }

}
