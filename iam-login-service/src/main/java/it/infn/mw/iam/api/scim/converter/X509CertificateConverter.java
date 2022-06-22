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
package it.infn.mw.iam.api.scim.converter;

import java.security.Principal;
import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParsingResult;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

@Service
public class X509CertificateConverter
    implements Converter<ScimX509Certificate, IamX509Certificate> {

  private final X509CertificateChainParser parser;


  @Autowired
  public X509CertificateConverter(X509CertificateChainParser parser) {
    this.parser = parser;
  }

  private String principalAsRfc2253String(Principal principal) {
    return X500NameUtils.getPortableRFC2253Form(principal.getName());
  }


  private IamX509Certificate parseCertificateFromString(String pemString) {
    X509CertificateChainParsingResult result = parser.parseChainFromString(pemString);

    IamX509Certificate cert = new IamX509Certificate();
    X509Certificate leafCert = result.getChain()[0];

    cert.setSubjectDn(principalAsRfc2253String(leafCert.getSubjectX500Principal()));
    cert.setIssuerDn(principalAsRfc2253String(leafCert.getIssuerX500Principal()));

    cert.setCertificate(pemString);
    return cert;
  }

  @Override
  public IamX509Certificate entityFromDto(ScimX509Certificate scim) {

    IamX509Certificate cert;

    if (scim.getPemEncodedCertificate() != null) {
      cert = parseCertificateFromString(scim.getPemEncodedCertificate());
    } else {
      cert = new IamX509Certificate();
      cert.setCertificate(scim.getPemEncodedCertificate());
      cert.setSubjectDn(scim.getSubjectDn());
      cert.setIssuerDn(scim.getIssuerDn());
    }

    cert.setLabel(scim.getDisplay());
    cert.setPrimary(scim.getPrimary() == null ? false : scim.getPrimary());

    return cert;
  }

  @Override
  public ScimX509Certificate dtoFromEntity(IamX509Certificate entity) {

    return ScimX509Certificate.builder()
      .created(entity.getCreationTime())
      .lastModified(entity.getLastUpdateTime())
      .display(entity.getLabel())
      .subjectDn(entity.getSubjectDn())
      .issuerDn(entity.getIssuerDn())
      .pemEncodedCertificate(entity.getCertificate())
      .primary(entity.isPrimary())
      .hasProxyCertificate(entity.hasProxy())
      .proxyExpirationTime(entity.hasProxy() ? entity.getProxy().getExpirationTime() : null)
      .build();
  }

}
