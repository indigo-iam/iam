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
package it.infn.mw.iam.config.lifecycle;

import javax.validation.Valid;
import javax.validation.constraints.Min;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("lifecycle")
@Configuration
@Validated
public class LifecycleProperties {

  public static class TaskProperties {
    boolean enabled = true;
    String cronSchedule = "0 */5 * * * *";

    public String getCronSchedule() {
      return cronSchedule;
    }

    public void setCronSchedule(String cronSchedule) {
      this.cronSchedule = cronSchedule;
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

  }
  public static class ExpiredAccountPolicyProperties {

    @Min(value = 0L)
    Long suspensionGracePeriodDays = 7L;

    @Min(value = 0L)
    Long removalGracePeriodDays = 30L;

    boolean removeExpiredAccounts = true;

    public Long getSuspensionGracePeriodDays() {
      return suspensionGracePeriodDays;
    }

    public void setSuspensionGracePeriodDays(Long suspensionGracePeriodDays) {
      this.suspensionGracePeriodDays = suspensionGracePeriodDays;
    }

    public Long getRemovalGracePeriodDays() {
      return removalGracePeriodDays;
    }

    public void setRemovalGracePeriodDays(Long removalGracePeriodDays) {
      this.removalGracePeriodDays = removalGracePeriodDays;
    }

    public boolean isRemoveExpiredAccounts() {
      return removeExpiredAccounts;
    }

    public void setRemoveExpiredAccounts(boolean removeExpiredAccounts) {
      this.removeExpiredAccounts = removeExpiredAccounts;
    }
  }

  public static class AccountLifecycleProperties {

    @Min(value = 0L)
    Integer accountLifetimeDays;

    @Valid
    ExpiredAccountPolicyProperties expiredAccountPolicy = new ExpiredAccountPolicyProperties();
    
    TaskProperties expiredAccountsTask = new TaskProperties();
    
    boolean readOnlyEndTime  = false;
    
    public Integer getAccountLifetimeDays() {
      return accountLifetimeDays;
    }

    public void setAccountLifetimeDays(Integer accountLifetimeDays) {
      this.accountLifetimeDays = accountLifetimeDays;
    }

    public ExpiredAccountPolicyProperties getExpiredAccountPolicy() {
      return expiredAccountPolicy;
    }

    public void setExpiredAccountPolicy(ExpiredAccountPolicyProperties expiredAccountPolicy) {
      this.expiredAccountPolicy = expiredAccountPolicy;
    }
    
    public TaskProperties getExpiredAccountsTask() {
      return expiredAccountsTask;
    }
    
    public void setExpiredAccountsTask(TaskProperties expiredAccountsTask) {
      this.expiredAccountsTask = expiredAccountsTask;
    }

    public boolean isReadOnlyEndTime() {
      return readOnlyEndTime;
    }

    public void setReadOnlyEndTime(boolean readOnlyEndTime) {
      this.readOnlyEndTime = readOnlyEndTime;
    }
    
  }

  @Valid
  AccountLifecycleProperties account = new AccountLifecycleProperties();

  public AccountLifecycleProperties getAccount() {
    return account;
  }

  public void setAccount(AccountLifecycleProperties account) {
    this.account = account;
  }

}
