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
package it.infn.mw.iam.config.oidc;

import java.util.Optional;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import com.google.common.base.Splitter;
import com.google.common.collect.Sets;

@Validated
@ConfigurationProperties(prefix = "oidc.jit-account-provisioning")
public class IamOidcJITAccountProvisioningProperties {

  private boolean enabled;
  private String trustedIdps = "all";
  private boolean cleanupTaskEnabled;
  private long cleanupTaskPeriodSec = 86400;
  private int inactiveAccountLifetimeDays = 15;

  // Getters e Setters
  public boolean isEnabled() {
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

  public boolean isCleanupTaskEnabled() {
    return cleanupTaskEnabled;
  }

  public void setCleanupTaskEnabled(boolean cleanupTaskEnabled) {
    this.cleanupTaskEnabled = cleanupTaskEnabled;
  }

  public long getCleanupTaskPeriodSec() {
    return cleanupTaskPeriodSec;
  }

  public void setCleanupTaskPeriodSec(long cleanupTaskPeriodSec) {
    this.cleanupTaskPeriodSec = cleanupTaskPeriodSec;
  }

  public int getInactiveAccountLifetimeDays() {
    return inactiveAccountLifetimeDays;
  }

  public void setInactiveAccountLifetimeDays(int inactiveAccountLifetimeDays) {
    this.inactiveAccountLifetimeDays = inactiveAccountLifetimeDays;
  }
}

