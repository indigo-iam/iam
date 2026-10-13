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
package it.infn.mw.iam.config.mfa;

import java.util.ArrayList;
import java.util.List;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@ConfigurationProperties(prefix = "mfa.passkey")
@Validated
public class IamPasskeyProperties {

  public enum UserVerification {
    REQUIRED("required"), PREFERRED("preferred"), DISCOURAGED("discouraged");

    private final String value;

    private UserVerification(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }
  }

  private boolean enabled = false;

  private boolean mandatory = false;

  private String rpId;

  private String rpName;

  private List<String> allowedOrigins = new ArrayList<>();

  private UserVerification userVerification = UserVerification.PREFERRED;

  @Min(1)
  @Max(50)
  private int maxCredentialsPerAccount = 5;

  @Min(30)
  @Max(3600)
  private int challengeTimeoutSeconds = 300;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isMandatory() {
    return mandatory;
  }

  public void setMandatory(boolean mandatory) {
    this.mandatory = mandatory;
  }

  public String getRpId() {
    return rpId;
  }

  public void setRpId(String rpId) {
    this.rpId = rpId;
  }

  public String getRpName() {
    return rpName;
  }

  public void setRpName(String rpName) {
    this.rpName = rpName;
  }

  public List<String> getAllowedOrigins() {
    return allowedOrigins;
  }

  public void setAllowedOrigins(List<String> allowedOrigins) {
    this.allowedOrigins = allowedOrigins;
  }

  public UserVerification getUserVerification() {
    return userVerification;
  }

  public void setUserVerification(UserVerification userVerification) {
    this.userVerification = userVerification;
  }

  public int getMaxCredentialsPerAccount() {
    return maxCredentialsPerAccount;
  }

  public void setMaxCredentialsPerAccount(int maxCredentialsPerAccount) {
    this.maxCredentialsPerAccount = maxCredentialsPerAccount;
  }

  public int getChallengeTimeoutSeconds() {
    return challengeTimeoutSeconds;
  }

  public void setChallengeTimeoutSeconds(int challengeTimeoutSeconds) {
    this.challengeTimeoutSeconds = challengeTimeoutSeconds;
  }
}
