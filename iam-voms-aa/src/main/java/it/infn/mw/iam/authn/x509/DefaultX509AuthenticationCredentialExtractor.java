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
package it.infn.mw.iam.authn.x509;

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.EEC;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.EEC_ISSUER_DN;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.EEC_SUBJECT_DN;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.ISSUER;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.SERIAL;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.SUBJECT;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.V_END;
import static it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor.Headers.V_START;

import java.util.EnumSet;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class DefaultX509AuthenticationCredentialExtractor
    implements X509AuthenticationCredentialExtractor {

  public enum Headers {
    CLIENT_CERT("X-SSL-Client-Cert"),
    SUBJECT("X-SSL-Client-S-Dn"),
    ISSUER("X-SSL-Client-I-Dn"),
    SERIAL("X-SSL-Client-Serial"),
    VERIFY("X-SSL-Client-Verify"),
    V_START("X-SSL-Client-V-Start"),
    V_END("X-SSL-Client-V-End"),
    PROTOCOL("X-SSL-Protocol"),
    SERVER_NAME("X-SSL-Server-Name"),
    EEC_SUBJECT_DN("X-ssl_client_ee_s_dn"),
    EEC_ISSUER_DN("x-ssl_client_ee_i_dn"),
    EEC("x-ssl_client_ee_cert");

    private final String header;

    private Headers(String header) {
      this.header = header;
    }

    public String getHeader() {
      return header;
    }
  }

  public static final Logger LOG =
      LoggerFactory.getLogger(DefaultX509AuthenticationCredentialExtractor.class);

  private final X509CertificateChainParser certChainParser;

  protected static final EnumSet<Headers> HEADERS_REQUIRED =
      EnumSet.of(EEC_SUBJECT_DN,
      EEC_ISSUER_DN, EEC, SUBJECT, ISSUER, SERIAL, V_START, V_END);

  @Autowired
  public DefaultX509AuthenticationCredentialExtractor(X509CertificateChainParser chainParser) {
    this.certChainParser = chainParser;
  }

  private String getHeader(HttpServletRequest request, Headers header) {
    return request.getHeader(header.header);
  }

  private boolean requiredHeadersPresent(HttpServletRequest request) {

    for (Headers e : HEADERS_REQUIRED) {
      if (isNullOrEmpty(request.getHeader(e.header))) {
        LOG.warn("Required header not found in: {}", e.header);
        return false;
      }
    }
    return true;
  }

  protected boolean hasProxyCertificate(HttpServletRequest request) {

    String eecSubjectDN = getHeader(request, EEC_SUBJECT_DN);

    if (isNullOrEmpty(eecSubjectDN)) {
      return false;
    }

    return !eecSubjectDN.equals(getHeader(request, SUBJECT));
  }

  private X509CertificateVerificationResult parseVerifyHeader(HttpServletRequest request) {
    String verifyHeaderContent = request.getHeader(VERIFY.header);

    if ("SUCCESS".equals(verifyHeaderContent)) {
      return X509CertificateVerificationResult.success();
    }

    // NGINX returns a client certificate validation failure in the following form:
    // FAILED:reason
    if (verifyHeaderContent.startsWith("FAILED:")) {
      String reason = verifyHeaderContent.substring(7); // skip the "FAILED:" preamble
      return X509CertificateVerificationResult.failed(reason);
    }

    final String errorMsg =
        String.format("Could not parse X.509 certificate verification header: %s : %s",
            VERIFY.header, verifyHeaderContent);

    LOG.error(errorMsg);
    throw new IllegalArgumentException(errorMsg);

  }

  @Override
  public Optional<IamX509AuthenticationCredential> extractX509Credential(
      HttpServletRequest request) {

    if (!requiredHeadersPresent(request)) {
      return Optional.empty();
    }

    IamX509AuthenticationCredential.Builder credBuilder =
        new IamX509AuthenticationCredential.Builder();

    String eecHeaderContent = getHeader(request, EEC);
    String pemCertificateString = eecHeaderContent.replace('\t', '\n');

    X509CertificateChainParsingResult chain =
        certChainParser.parseChainFromString(pemCertificateString);

    credBuilder.certificateChain(chain.getChain())
      .certificateChainPemString(chain.getPemString())
      .subject(getHeader(request, EEC_SUBJECT_DN))
      .issuer(getHeader(request, EEC_ISSUER_DN))
      .verificationResult(parseVerifyHeader(request));

    final IamX509AuthenticationCredential cred = credBuilder.build();
    LOG.debug("Extracted X.509 credential: {}", cred);
    return Optional.of(cred);
  }

}
