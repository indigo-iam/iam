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
package it.infn.mw.iam.test.scim.converter;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.authn.x509.PEMX509CertificateChainParser;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;


public class ScimX509CertificateConverterTests extends X509TestSupport {

  X509CertificateConverter converter =
      new X509CertificateConverter(new PEMX509CertificateChainParser());

  @Test
  public void testScimToEntityConversion() {

    ScimX509Certificate scimCert = ScimX509Certificate.builder()
      .display("A label")
      .primary(true)
      .subjectDn(TEST_0_SUBJECT)
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .build();

    IamX509Certificate iamCert = converter.entityFromDto(scimCert);

    assertThat(iamCert.getLabel(), equalTo("A label"));
    assertTrue(iamCert.isPrimary());
    assertThat(iamCert.getSubjectDn(), equalTo(TEST_0_SUBJECT));
    assertThat(iamCert.getCertificate(), equalTo(TEST_0_CERT_STRING));
    assertThat(iamCert.getAccount(), nullValue());
  }

  @Test
  public void testEntityToScimConversion() {

    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(TEST_0_SUBJECT);
    cert.setCertificate(TEST_0_CERT_STRING);
    cert.setLabel("A label");
    cert.setPrimary(false);

    ScimX509Certificate scimCert = converter.dtoFromEntity(cert);

    assertThat(scimCert.getDisplay(), equalTo("A label"));
    assertFalse(scimCert.getPrimary());
    assertThat(scimCert.getSubjectDn(), equalTo(TEST_0_SUBJECT));
    assertThat(scimCert.getPemEncodedCertificate(), equalTo(TEST_0_CERT_STRING));

  }
}
