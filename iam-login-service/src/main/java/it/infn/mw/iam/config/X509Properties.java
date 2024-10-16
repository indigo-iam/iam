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
@ConfigurationProperties("x509")
public class X509Properties {

    private String trustAnchorsDir;
    private Long trustAnchorsRefreshMsec;
    private String tlsVersion;

    public String getTrustAnchorsDir() {
        return trustAnchorsDir;
    }

    public void setTrustAnchorsDir(String trustAnchorsDir) {
        this.trustAnchorsDir = trustAnchorsDir;
    }

    public Long getTrustAnchorsRefreshMsec() {
        return trustAnchorsRefreshMsec;
    }

    public void setTrustAnchorsRefreshMsec(Long trustAnchorsRefreshMsec) {
        this.trustAnchorsRefreshMsec = trustAnchorsRefreshMsec;
    }

    public String getTlsVersion() {
        return tlsVersion;
    }

    public void setTlsVersion(String tlsVersion) {
        this.tlsVersion = tlsVersion;
    }

}
