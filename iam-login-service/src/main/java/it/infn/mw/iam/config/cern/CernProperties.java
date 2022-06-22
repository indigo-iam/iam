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
package it.infn.mw.iam.config.cern;

import javax.validation.Valid;
import javax.validation.constraints.Min;

import javax.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@ConfigurationProperties("cern")
@Validated
public class CernProperties {

  public static class HrSynchTaskProperties {

    boolean enabled = true;

    @NotBlank
    String cronSchedule = "0 23 */12 * * *";

    @Min(value = 5L)
    int pageSize = 50;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public String getCronSchedule() {
      return cronSchedule;
    }

    public void setCronSchedule(String cronSchedule) {
      this.cronSchedule = cronSchedule;
    }

    public int getPageSize() {
      return pageSize;
    }

    public void setPageSize(int pageSize) {
      this.pageSize = pageSize;
    }

  }

  public static class HrDbApiProperties {

    @NotBlank
    String url = "http://hr.test.example";

    @NotBlank
    String username = "username";

    @NotBlank
    String password = "password";

    public String getUrl() {
      return url;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public String getUsername() {
      return username;
    }

    public void setUsername(String username) {
      this.username = username;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String password) {
      this.password = password;
    }
  }

  @NotBlank
  private String ssoIssuer = "https://auth.cern.ch/auth/realms/cern";

  @NotBlank
  private String personIdClaim = "cern_person_id";

  @NotBlank
  private String experimentName = "test";

  @Valid
  private HrDbApiProperties hrApi = new HrDbApiProperties();

  @Valid
  private HrSynchTaskProperties task = new HrSynchTaskProperties();

  public HrDbApiProperties getHrApi() {
    return hrApi;
  }

  public void setHrApi(HrDbApiProperties hrApi) {
    this.hrApi = hrApi;
  }

  public String getExperimentName() {
    return experimentName;
  }

  public void setExperimentName(String experimentName) {
    this.experimentName = experimentName;
  }

  public void setSsoIssuer(String ssoIssuer) {
    this.ssoIssuer = ssoIssuer;
  }

  public String getSsoIssuer() {
    return ssoIssuer;
  }

  public String getPersonIdClaim() {
    return personIdClaim;
  }

  public void setPersonIdClaim(String personIdClaim) {
    this.personIdClaim = personIdClaim;
  }

  public HrSynchTaskProperties getTask() {
    return task;
  }

  public void setTask(HrSynchTaskProperties task) {
    this.task = task;
  }
}
