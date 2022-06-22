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
package it.infn.mw.iam.rcauth;

import static java.lang.String.format;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.rcauth.x509.CertificateRequestHolder;
import it.infn.mw.iam.rcauth.x509.CertificateRequestUtil;

@Component
@ConditionalOnProperty(name = "rcauth.enabled", havingValue = "true")
public class DefaultRCAuthCertificateRequestor implements RCAuthCertificateRequestor {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultRCAuthCertificateRequestor.class);

  final RCAuthProperties properties;
  final RestTemplateFactory restFactory;

  @Autowired
  public DefaultRCAuthCertificateRequestor(RCAuthProperties properties, RestTemplateFactory rf) {
    this.properties = properties;
    this.restFactory = rf;
  }

  protected HttpEntity<MultiValueMap<String, String>> prepareCertificateRequest(String accessToken,
      String certReq) {
    HttpHeaders headers = new HttpHeaders();

    headers.add("Authorization", format("Bearer %s", accessToken));
    

    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    params.add("client_id", properties.getClientId());
    params.add("client_secret", properties.getClientSecret());
    params.add("certreq", certReq);
    params.add("certlifetime", Long.toString(properties.getCertLifetimeSeconds()));

    return new HttpEntity<>(params, headers);
  }

  protected String rcauthGetCertUrl() {
    return String.format("%s/getcert", properties.getIssuer());
  }

  @Override
  public X509Certificate getCertificate(String accessToken, CertificateRequestHolder holder) {

    RestTemplate rt = restFactory.newRestTemplate();

    try {

      String certRequest = CertificateRequestUtil.certRequestToBase64String(holder.getRequest());

      String responseBody = rt.postForObject(rcauthGetCertUrl(),
          prepareCertificateRequest(accessToken, certRequest), String.class);

      InputStream bais = IOUtils.toInputStream(responseBody);
      return CertificateUtils.loadCertificate(bais, Encoding.PEM);

    } catch (RestClientException | IOException e) {
      LOG.debug(e.getMessage(), e);
      throw new RCAuthError(e.getMessage(), e);
    }
  }
}
