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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

/**
 * PublicKeyCredentialCreationOptions in the JSON form consumed by navigator.credentials.create().
 * Binary fields are base64url encoded
 */
@JsonInclude(Include.NON_NULL)
public class PasskeyRegistrationOptionsDTO {

  public static class RelyingParty {
    private String id;
    private String name;

    public RelyingParty() {
      // empty constructor
    }

    public RelyingParty(String id, String name) {
      this.id = id;
      this.name = name;
    }

    public String getId() {
      return id;
    }

    public void setId(String id) {
      this.id = id;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }
  }

  public static class User {
    private String id;
    private String name;
    private String displayName;

    public User() {
      // empty constructor
    }

    public User(String id, String name, String displayName) {
      this.id = id;
      this.name = name;
      this.displayName = displayName;
    }

    public String getId() {
      return id;
    }

    public void setId(String id) {
      this.id = id;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getDisplayName() {
      return displayName;
    }

    public void setDisplayName(String displayName) {
      this.displayName = displayName;
    }
  }

  public static class CredentialParameters {
    private String type = PasskeyCredentialDescriptorDTO.PUBLIC_KEY_TYPE;
    private long alg;

    public CredentialParameters() {
      // empty constructor
    }

    public CredentialParameters(long alg) {
      this.alg = alg;
    }

    public String getType() {
      return type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public long getAlg() {
      return alg;
    }

    public void setAlg(long alg) {
      this.alg = alg;
    }
  }

  public static class AuthenticatorSelection {
    private String residentKey;
    private String userVerification;

    public AuthenticatorSelection() {
      // empty constructor
    }

    public AuthenticatorSelection(String residentKey, String userVerification) {
      this.residentKey = residentKey;
      this.userVerification = userVerification;
    }

    public String getResidentKey() {
      return residentKey;
    }

    public void setResidentKey(String residentKey) {
      this.residentKey = residentKey;
    }

    public String getUserVerification() {
      return userVerification;
    }

    public void setUserVerification(String userVerification) {
      this.userVerification = userVerification;
    }
  }

  private RelyingParty rp;
  private User user;
  private String challenge;
  private List<CredentialParameters> pubKeyCredParams;
  private long timeout;
  private List<PasskeyCredentialDescriptorDTO> excludeCredentials;
  private AuthenticatorSelection authenticatorSelection;
  private String attestation;

  public RelyingParty getRp() {
    return rp;
  }

  public void setRp(RelyingParty rp) {
    this.rp = rp;
  }

  public User getUser() {
    return user;
  }

  public void setUser(User user) {
    this.user = user;
  }

  public String getChallenge() {
    return challenge;
  }

  public void setChallenge(String challenge) {
    this.challenge = challenge;
  }

  public List<CredentialParameters> getPubKeyCredParams() {
    return pubKeyCredParams;
  }

  public void setPubKeyCredParams(List<CredentialParameters> pubKeyCredParams) {
    this.pubKeyCredParams = pubKeyCredParams;
  }

  public long getTimeout() {
    return timeout;
  }

  public void setTimeout(long timeout) {
    this.timeout = timeout;
  }

  public List<PasskeyCredentialDescriptorDTO> getExcludeCredentials() {
    return excludeCredentials;
  }

  public void setExcludeCredentials(List<PasskeyCredentialDescriptorDTO> excludeCredentials) {
    this.excludeCredentials = excludeCredentials;
  }

  public AuthenticatorSelection getAuthenticatorSelection() {
    return authenticatorSelection;
  }

  public void setAuthenticatorSelection(AuthenticatorSelection authenticatorSelection) {
    this.authenticatorSelection = authenticatorSelection;
  }

  public String getAttestation() {
    return attestation;
  }

  public void setAttestation(String attestation) {
    this.attestation = attestation;
  }
}
