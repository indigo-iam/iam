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
package it.infn.mw.iam.util.x509;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import it.infn.mw.iam.api.scim.exception.ScimValidationException;

public class X509Utils {

  private X509Utils() {}

  public static X509Certificate getX509CertificateFromString(String certValue) {

    byte[] base64decoded = null;
    try {

      base64decoded = Base64.getDecoder().decode(certValue);

    } catch (IllegalArgumentException iae) {

      throw new ScimValidationException(
          "Error in conversion from String to x509 certificate: Not valid Base64 scheme", iae);
    }

    X509Certificate cert = null;

    try {

      cert = (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(base64decoded));

    } catch (CertificateException ce) {

      throw new ScimValidationException(
          "Error in conversion from String to x509 certificate: the base64 encoded string is not a valid certificate",
          ce);
    }

    return cert;
  }

  public static String getCertificateSubject(X509Certificate cert) {

    return X500NameUtils.getReadableForm(cert.getIssuerX500Principal());
  }

  public static String getCertificateSubject(String certValueAsString) {

    return getCertificateSubject(getX509CertificateFromString(certValueAsString));
  }

}
