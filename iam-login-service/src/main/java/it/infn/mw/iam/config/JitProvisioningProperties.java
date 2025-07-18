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

import static java.lang.Boolean.FALSE;

import java.util.Optional;
import java.util.Set;

import com.google.common.base.Splitter;
import com.google.common.collect.Sets;

public abstract class JitProvisioningProperties {

  private Boolean enabled = FALSE;
  private String trustedIdps = "all";

  public Boolean getEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getTrustedIdps() {
    return trustedIdps;
  }

  public void setTrustedIdps(String trustedIdps) {
    this.trustedIdps = trustedIdps;
  }

  public Optional<Set<String>> getTrustedIdpsAsOptionalSet() {
    if ("all".equals(trustedIdps)) {
      return Optional.empty();
    }

    Set<String> trustedIdpIds =
        Sets.newHashSet(Splitter.on(",").trimResults().omitEmptyStrings().split(trustedIdps));

    if (trustedIdpIds.isEmpty()) {
      return Optional.empty();
    }

    return Optional.of(trustedIdpIds);
  }
}
