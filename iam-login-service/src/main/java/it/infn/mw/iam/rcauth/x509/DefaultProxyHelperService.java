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
package it.infn.mw.iam.rcauth.x509;

import static org.italiangrid.voms.util.CredentialsUtils.saveProxyCredentials;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Clock;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyType;

@Service
public class DefaultProxyHelperService implements ProxyHelperService {
  public static final int DEFAULT_KEY_SIZE = 2048;

  final Clock clock;

  @Autowired
  public DefaultProxyHelperService(Clock clock) {
    this.clock = clock;
  }

  @Override
  public ProxyCertificate generateProxy(X509Certificate cert, PrivateKey key) {

    ProxyCertificateOptions options = new ProxyCertificateOptions(new X509Certificate[] {cert});
    options.setKeyLength(DEFAULT_KEY_SIZE);
    options.setType(ProxyType.RFC3820);

    options.setValidityBounds(Date.from(clock.instant()), cert.getNotAfter());

    try {
      return ProxyGenerator.generate(options, key);
    } catch (InvalidKeyException | CertificateParsingException | SignatureException
        | NoSuchAlgorithmException | IOException e) {
      throw new ProxyGenerationError(e);
    }

  }

  @Override
  public String proxyCertificateToPemString(ProxyCertificate proxy) {
    ByteArrayOutputStream proxyOs = new ByteArrayOutputStream();
    try {
      saveProxyCredentials(proxyOs, proxy.getCredential());
      proxyOs.flush();
      return proxyOs.toString();
    } catch (IllegalStateException | IOException e) {
      throw new ProxyGenerationError("Error serializing proxy certificate: " + e.getMessage(), e);
    }
  }

  @Override
  public ProxyCertificate generateProxy(PEMCredential proxyCredential, long lifetimeInSecs) {

    ProxyCertificateOptions options =
        new ProxyCertificateOptions(proxyCredential.getCertificateChain());

    options.setKeyLength(DEFAULT_KEY_SIZE);
    options.setType(ProxyType.RFC3820);

    final Instant now = clock.instant();
    final Instant eol = now.plusSeconds(lifetimeInSecs);

    options.setValidityBounds(Date.from(now), Date.from(eol));

    try {
      return ProxyGenerator.generate(options, proxyCredential.getKey());
    } catch (InvalidKeyException | CertificateParsingException | SignatureException
        | NoSuchAlgorithmException | IOException e) {
      throw new ProxyGenerationError(e);
    }
  }

  @Override
  public PEMCredential credentialFromPemString(String pemString) {

    ByteArrayInputStream bais = new ByteArrayInputStream(pemString.getBytes());
    try {
      return new PEMCredential(bais, (char[]) null);
    } catch (KeyStoreException | CertificateException | IOException e) {
      throw new ProxyGenerationError(
          "Error reading proxy certificate from string: " + e.getMessage(), e);
    }
  }

}
