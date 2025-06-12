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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "mfa")
public class IamTotpMfaProperties {

  private boolean multiFactorSettingsBtnEnabled;
  private String passwordToEncryptAndDecrypt;
  private String oldPasswordToDecrypt;
  private boolean updateGlobalKeyRequest;

  public String getPasswordToEncryptOrDecrypt() {
    return passwordToEncryptAndDecrypt;
  }

  public void setPasswordToEncryptAndDecrypt(String passwordToEncryptAndDecrypt) {
    this.passwordToEncryptAndDecrypt = passwordToEncryptAndDecrypt;
  }

  public void setMultiFactorSettingsBtnEnabled(boolean multiFactorSettingsBtnEnabled) {
    this.multiFactorSettingsBtnEnabled = multiFactorSettingsBtnEnabled;
  }

  public boolean hasMultiFactorSettingsBtnEnabled() {
    return multiFactorSettingsBtnEnabled;
  }

  public void setOldPasswordToDecrypt(String oldPasswordToDecrypt) {
    this.oldPasswordToDecrypt = oldPasswordToDecrypt;
  }

  public String getOldPasswordToDecrypt() {
    return oldPasswordToDecrypt;
  }

  public void setUpdateGlobalKeyRequest(boolean updateGlobalKeyRequest) {
    this.updateGlobalKeyRequest = updateGlobalKeyRequest;
  }

  public boolean isUpdateGlobalKeyRequest() {
    return updateGlobalKeyRequest;
  }

}
