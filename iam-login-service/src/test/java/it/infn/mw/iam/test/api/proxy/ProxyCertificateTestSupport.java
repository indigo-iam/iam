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
package it.infn.mw.iam.test.api.proxy;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.util.MultiValueMap;

import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyType;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;
import it.infn.mw.iam.test.api.tokens.MultiValueMapBuilder;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;

public class ProxyCertificateTestSupport extends X509TestSupport {

  public static final String TEST_USER_USERNAME = "test";

  public static final long DEFAULT_PROXY_LIFETIME_SECONDS = TimeUnit.HOURS.toSeconds(12);
  public static final int DEFAULT_KEY_SIZE = 2048;

  protected static final MultiValueMap<String, String> CLIENT_AUTH_PARAMS =
      MultiValueMapBuilder.builder()
        .singleStringParam("client_id", "password-grant")
        .singleStringParam("client_secret", "secret")
        .build();

  protected String generateTest0Proxy(ProxyHelperService proxyHelper, Date notBefore, Date notAfter)
      throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException,
      KeyStoreException, CertificateException {

    PEMCredential pemCredential = getTest0PemCredential();
    ProxyCertificateOptions opts = new ProxyCertificateOptions(pemCredential.getCertificateChain());
    opts.setValidityBounds(notBefore, notAfter);
    opts.setType(ProxyType.RFC3820);
    ProxyCertificate proxy = ProxyGenerator.generate(opts, pemCredential.getKey());
    return proxyHelper.proxyCertificateToPemString(proxy);
  }

}
