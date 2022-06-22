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
package it.infn.mw.iam.config.client_registration;

import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ANYONE;

import java.util.concurrent.TimeUnit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties("client-registration")
@Configuration
public class ClientRegistrationProperties {

  public static class ClientDefaultsProperties {

    private int defaultAccessTokenValiditySeconds = (int) TimeUnit.HOURS.toSeconds(1);
    private int defaultIdTokenValiditySeconds = (int) TimeUnit.MINUTES.toSeconds(10);
    private int defaultDeviceCodeValiditySeconds = (int) TimeUnit.MINUTES.toSeconds(10);
    private int defaultRefreshTokenValiditySeconds = -1;

    private int defaultRegistrationAccessTokenValiditySeconds = -1;

    public int getDefaultAccessTokenValiditySeconds() {
      return defaultAccessTokenValiditySeconds;
    }

    public void setDefaultAccessTokenValiditySeconds(int defaultAccessTokenValiditySeconds) {
      this.defaultAccessTokenValiditySeconds = defaultAccessTokenValiditySeconds;
    }

    public int getDefaultIdTokenValiditySeconds() {
      return defaultIdTokenValiditySeconds;
    }

    public void setDefaultIdTokenValiditySeconds(int defaultIdTokenValiditySeconds) {
      this.defaultIdTokenValiditySeconds = defaultIdTokenValiditySeconds;
    }

    public int getDefaultDeviceCodeValiditySeconds() {
      return defaultDeviceCodeValiditySeconds;
    }

    public void setDefaultDeviceCodeValiditySeconds(int defaultDeviceCodeValiditySeconds) {
      this.defaultDeviceCodeValiditySeconds = defaultDeviceCodeValiditySeconds;
    }

    public int getDefaultRefreshTokenValiditySeconds() {
      return defaultRefreshTokenValiditySeconds;
    }

    public void setDefaultRefreshTokenValiditySeconds(int defaultRefreshTokenValiditySeconds) {
      this.defaultRefreshTokenValiditySeconds = defaultRefreshTokenValiditySeconds;
    }

    public int getDefaultRegistrationAccessTokenValiditySeconds() {
      return defaultRegistrationAccessTokenValiditySeconds;
    }

    public void setDefaultRegistrationAccessTokenValiditySeconds(
        int defaultRegistrationAccessTokenValiditySeconds) {
      this.defaultRegistrationAccessTokenValiditySeconds =
          defaultRegistrationAccessTokenValiditySeconds;
    }

  }

  public enum ClientRegistrationAuthorizationPolicy {
    ADMINISTRATORS,
    REGISTERED_USERS,
    ANYONE
  }
  
  private ClientRegistrationAuthorizationPolicy allowFor = ANYONE;

  private ClientDefaultsProperties clientDefaults = new ClientDefaultsProperties();

  private boolean enable = true;

  public ClientRegistrationAuthorizationPolicy getAllowFor() {
    return allowFor;
  }

  public void setAllowFor(ClientRegistrationAuthorizationPolicy allowFor) {
    this.allowFor = allowFor;
  }

  public ClientDefaultsProperties getClientDefaults() {
    return clientDefaults;
  }

  public void setClientDefaults(ClientDefaultsProperties clientDefaults) {
    this.clientDefaults = clientDefaults;
  }

  public boolean isEnable() {
    return enable;
  }

  public void setEnable(boolean enable) {
    this.enable = enable;
  }

}
