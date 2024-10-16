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

import javax.net.ssl.X509TrustManager;

import org.italiangrid.voms.util.CertificateValidatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;
import it.infn.mw.iam.authn.x509.DummyX509TrustManager;

@Configuration
public class X509CommonTrustConfig {

  @Bean
  X509TrustManager trustManager(X509Properties x509Properties) {
    X509TrustManager tm;
    try {
      X509CertChainValidatorExt certificateValidator =
          new CertificateValidatorBuilder().lazyAnchorsLoading(false)
            .trustAnchorsDir(x509Properties.getTrustAnchorsDir())
            .trustAnchorsUpdateInterval(x509Properties.getTrustAnchorsRefreshMsec().longValue())
            .build();
      tm = SocketFactoryCreator.getSSLTrustManager(certificateValidator);
    } catch (Exception e) {
      tm = DummyX509TrustManager.INSTANCE;
    }
    return tm;
  }

}
