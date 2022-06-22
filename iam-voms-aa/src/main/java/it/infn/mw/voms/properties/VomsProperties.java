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
package it.infn.mw.voms.properties;

import java.util.concurrent.TimeUnit;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Positive;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("voms")
public class VomsProperties {

  public static class TLSProperties {
    @NotBlank
    String certificatePath;

    @NotBlank
    String privateKeyPath;

    @NotBlank
    String trustAnchorsDir;

    @Positive
    long trustAnchorsRefreshIntervalSecs = 86400;

    public String getCertificatePath() {
      return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
      this.certificatePath = certificatePath;
    }

    public String getPrivateKeyPath() {
      return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
      this.privateKeyPath = privateKeyPath;
    }

    public String getTrustAnchorsDir() {
      return trustAnchorsDir;
    }

    public void setTrustAnchorsDir(String trustAnchorsDir) {
      this.trustAnchorsDir = trustAnchorsDir;
    }

    public long getTrustAnchorsRefreshIntervalSecs() {
      return trustAnchorsRefreshIntervalSecs;
    }

    public void setTrustAnchorsRefreshIntervalSecs(long trustAnchorsRefreshIntervalSecs) {
      this.trustAnchorsRefreshIntervalSecs = trustAnchorsRefreshIntervalSecs;
    }
  }

  @Valid
  public static class VOMSTrustStoreProperties {

    @NotBlank
    String dir;

    long refreshIntervalSec = TimeUnit.HOURS.toSeconds(24);

    public String getDir() {
      return dir;
    }

    public void setDir(String dir) {
      this.dir = dir;
    }

    public long getRefreshIntervalSec() {
      return refreshIntervalSec;
    }

    public void setRefreshIntervalSec(long refreshIntervalSec) {
      this.refreshIntervalSec = refreshIntervalSec;
    }
  }

  @Valid
  public static class VOMSAAProperties {

    @NotBlank
    private String voName;

    @NotBlank
    private String host;

    private int port = 15000;

    private long maxAcLifetimeInSeconds = TimeUnit.HOURS.toSeconds(12);

    private Boolean useLegacyFqanEncoding = Boolean.FALSE;
    
    private String optionalGroupLabel = "wlcg.optional-group";

    public String getVoName() {
      return voName;
    }

    public void setVoName(String voName) {
      this.voName = voName;
    }

    public String getHost() {
      return host;
    }

    public void setHost(String host) {
      this.host = host;
    }

    public int getPort() {
      return port;
    }

    public void setPort(int port) {
      this.port = port;
    }

    public long getMaxAcLifetimeInSeconds() {
      return maxAcLifetimeInSeconds;
    }

    public void setMaxAcLifetimeInSeconds(long maxAcLifetimeInSeconds) {
      this.maxAcLifetimeInSeconds = maxAcLifetimeInSeconds;
    }
    
    public String getOptionalGroupLabel() {
      return optionalGroupLabel;
    }
    
    public void setOptionalGroupLabel(String optionalGroupLabel) {
      this.optionalGroupLabel = optionalGroupLabel;
    }
    
    public void setUseLegacyFqanEncoding(Boolean useLegacyFqanEncoding) {
      this.useLegacyFqanEncoding = useLegacyFqanEncoding;
    }
    
    public Boolean getUseLegacyFqanEncoding() {
      return useLegacyFqanEncoding;
    }
  }

  private TLSProperties tls;
  private VOMSTrustStoreProperties trust;
  private VOMSAAProperties aa;

  public TLSProperties getTls() {
    return tls;
  }

  public void setTls(TLSProperties tls) {
    this.tls = tls;
  }

  public VOMSTrustStoreProperties getTrust() {
    return trust;
  }

  public void setTrust(VOMSTrustStoreProperties trust) {
    this.trust = trust;
  }

  public VOMSAAProperties getAa() {
    return aa;
  }

  public void setAa(VOMSAAProperties aa) {
    this.aa = aa;
  }
}
