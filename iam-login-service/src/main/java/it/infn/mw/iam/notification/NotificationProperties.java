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
package it.infn.mw.iam.notification;

import static it.infn.mw.iam.notification.NotificationProperties.AdminNotificationPolicy.NOTIFY_ADDRESS;
import static it.infn.mw.iam.notification.NotificationProperties.GroupManagerNotificationPolicy.NOTIFY_GMS_AND_ADMINS;

import java.util.Map;

import javax.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Validated
@ConfigurationProperties(prefix = "notification")
public class NotificationProperties {

  public enum AdminNotificationPolicy {
    NOTIFY_ADDRESS,
    NOTIFY_ADMINS,
    NOTIFY_ADDRESS_AND_ADMINS
  }

  public enum GroupManagerNotificationPolicy {
    NOTIFY_GMS,
    NOTIFY_GMS_AND_ADMINS
  }

  private Boolean disable;

  @NotBlank
  private String mailFrom;

  private long taskDelay;
  private Integer cleanupAge;

  @NotBlank
  private String adminAddress;

  private Map<String, String> subject;

  private AdminNotificationPolicy adminNotificationPolicy = NOTIFY_ADDRESS;

  private GroupManagerNotificationPolicy groupManagerNotificationPolicy =
      NOTIFY_GMS_AND_ADMINS;

  public Boolean getDisable() {
    return disable;
  }

  public void setDisable(Boolean disable) {
    this.disable = disable;
  }

  public String getMailFrom() {
    return mailFrom;
  }

  public void setMailFrom(String mailFrom) {
    this.mailFrom = mailFrom;
  }

  public long getTaskDelay() {
    return taskDelay;
  }

  public void setTaskDelay(long taskDelay) {
    this.taskDelay = taskDelay;
  }

  public Integer getCleanupAge() {
    return cleanupAge;
  }

  public void setCleanupAge(Integer cleanupAge) {
    this.cleanupAge = cleanupAge;
  }

  public String getAdminAddress() {
    return adminAddress;
  }

  public void setAdminAddress(String adminAddress) {
    this.adminAddress = adminAddress;
  }

  public Map<String, String> getSubject() {
    return subject;
  }

  public void setSubject(Map<String, String> subject) {
    this.subject = subject;
  }

  public AdminNotificationPolicy getAdminNotificationPolicy() {
    return adminNotificationPolicy;
  }

  public void setAdminNotificationPolicy(AdminNotificationPolicy adminNotificationPolicy) {
    this.adminNotificationPolicy = adminNotificationPolicy;
  }

  public GroupManagerNotificationPolicy getGroupManagerNotificationPolicy() {
    return groupManagerNotificationPolicy;
  }

  public void setGroupManagerNotificationPolicy(
      GroupManagerNotificationPolicy groupManagerNotificationPolicy) {
    this.groupManagerNotificationPolicy = groupManagerNotificationPolicy;
  }
}
