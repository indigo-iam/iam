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

import org.springframework.stereotype.Component;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParsingResult;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

@Component
public class X509CertificateParser {
    
    private final X509CertificateChainParser chainParser;

    public X509CertificateParser(X509CertificateChainParser chainParser) {
        this.chainParser = chainParser;
    }

    private String principalAsRfc2253String(Principal principal) {
        return X500NameUtils.getPortableRFC2253Form(principal.getName());
    }

    public IamX509Certificate parseCertificateFromString(String pemString) {
        X509CertificateChainParsingResult result = chainParser.parseChainFromString(pemString);

        IamX509Certificate cert = new IamX509Certificate();
        X509Certificate leafCert = result.getChain()[0];

        cert.setSubjectDn(principalAsRfc2253String(leafCert.getSubjectX500Principal()));
        cert.setIssuerDn(principalAsRfc2253String(leafCert.getIssuerX500Principal()));

        cert.setCertificate(pemString);
        return cert;
    }
}
