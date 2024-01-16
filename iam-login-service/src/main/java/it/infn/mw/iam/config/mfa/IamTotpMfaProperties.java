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

  private boolean editMultiFactorSettingsBtnEnabled;
  private String passwordToEncryptAndDecrypt;
  private String oldPasswordToEncryptAndDecrypt;
  private boolean updateKeyRequest;

  public void setEditMultiFactorSettingsBtnEnabled(boolean editMultiFactorSettingsBtnEnabled) {
    this.editMultiFactorSettingsBtnEnabled = editMultiFactorSettingsBtnEnabled;
  }

  public boolean isEditMultiFactorSettingsBtnEnabled() {
    return editMultiFactorSettingsBtnEnabled;
  }

  public String getPasswordToEncryptOrDecrypt() {
    return passwordToEncryptAndDecrypt;
  }

  public void setPasswordToEncryptAndDecrypt(String passwordToEncryptAndDecrypt) {
    this.passwordToEncryptAndDecrypt = passwordToEncryptAndDecrypt;
  }

  public String getOldPasswordToEncryptAndDecrypt() {
    return oldPasswordToEncryptAndDecrypt;
  }

  public void setOldPasswordToEncryptAndDecrypt(String oldPasswordToEncryptAndDecrypt) {
    this.oldPasswordToEncryptAndDecrypt = oldPasswordToEncryptAndDecrypt;
  }

  public boolean isUpdateKeyRequest() {
    return updateKeyRequest;
  }

  public void setUpdateKeyRequest(boolean updateKeyRequest) {
    this.updateKeyRequest = updateKeyRequest;
  }
}
