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
package it.infn.mw.iam.api.requests.validator;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.beans.factory.annotation.Autowired;

import com.google.common.base.Strings;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.api.scim.converter.X509CertificateParser;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

public class CertLinkRequestValidator
        implements ConstraintValidator<CertLinkRequest, CertLinkRequestDTO> {

    @Autowired
    private X509CertificateParser parser;

    public CertLinkRequestValidator() {
        // empty
    }

    @Override
    public void initialize(CertLinkRequest constraintAnnotation) {
        // empty
    }

    private boolean missingPemAndDn(CertLinkRequestDTO value) {
        return Strings.isNullOrEmpty(value.getPemEncodedCertificate())
                && (Strings.isNullOrEmpty(value.getSubjectDn())
                        || Strings.isNullOrEmpty(value.getIssuerDn()));
    }

    private boolean inconsistentSubject(CertLinkRequestDTO value, IamX509Certificate cert) {
        return !Strings.isNullOrEmpty(value.getPemEncodedCertificate())
                && (!X500NameUtils.equal(X500NameUtils.getComparableForm(value.getSubjectDn()),
                        X500NameUtils.getComparableForm(cert.getSubjectDn())));
    }

    private boolean inconsistentIssuer(CertLinkRequestDTO value, IamX509Certificate cert) {
        return !Strings.isNullOrEmpty(value.getPemEncodedCertificate())
                && (!X500NameUtils.equal(X500NameUtils.getComparableForm(value.getIssuerDn()),
                        X500NameUtils.getComparableForm(cert.getIssuerDn())));
    }

    @Override
    public boolean isValid(CertLinkRequestDTO value, ConstraintValidatorContext context) {

        try {
            if (value == null) {
                return false;
            }
            if (missingPemAndDn(value)) {
                return false;
            }
            if (!Strings.isNullOrEmpty(value.getPemEncodedCertificate())) {
                IamX509Certificate cert =
                        parser.parseCertificateFromString(value.getPemEncodedCertificate());
                if (inconsistentSubject(value, cert) || inconsistentIssuer(value, cert)) {
                    return false;
                }
            }
            return true;
        } catch (

        Exception e) {
            return false;
        }

    }
}
