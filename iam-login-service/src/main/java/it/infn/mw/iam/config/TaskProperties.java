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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "task")
public class TaskProperties {

  private long aupReminder;
  private long tokenCleanupPeriodMsec;
  private long approvalCleanupPeriodMsec;
  private long deviceCodeCleanupPeriodMsec;
  private long wellKnownCacheCleanupPeriodSecs;

  public long getAupReminder() {
    return aupReminder;
  }

  public void setAupReminder(long aupReminder) {
    this.aupReminder = aupReminder;
  }

  public long getTokenCleanupPeriodMsec() {
    return tokenCleanupPeriodMsec;
  }

  public void setTokenCleanupPeriodMsec(long tokenCleanupPeriodMsec) {
    this.tokenCleanupPeriodMsec = tokenCleanupPeriodMsec;
  }

  public long getApprovalCleanupPeriodMsec() {
    return approvalCleanupPeriodMsec;
  }

  public void setApprovalCleanupPeriodMsec(long approvalCleanupPeriodMsec) {
    this.approvalCleanupPeriodMsec = approvalCleanupPeriodMsec;
  }

  public long getDeviceCodeCleanupPeriodMsec() {
    return deviceCodeCleanupPeriodMsec;
  }

  public void setDeviceCodeCleanupPeriodMsec(long deviceCodeCleanupPeriodMsec) {
    this.deviceCodeCleanupPeriodMsec = deviceCodeCleanupPeriodMsec;
  }

  public long getWellKnownCacheCleanupPeriodSecs() {
    return wellKnownCacheCleanupPeriodSecs;
  }

  public void setWellKnownCacheCleanupPeriodSecs(long wellKnownCacheCleanupPeriodSecs) {
    this.wellKnownCacheCleanupPeriodSecs = wellKnownCacheCleanupPeriodSecs;
  }


}
