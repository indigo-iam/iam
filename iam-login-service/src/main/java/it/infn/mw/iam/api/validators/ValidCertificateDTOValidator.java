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
package it.infn.mw.iam.api.validators;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.beans.factory.annotation.Autowired;

import com.google.common.base.Strings;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import it.infn.mw.iam.api.requests.model.CertificateDTO;
import it.infn.mw.iam.api.scim.converter.X509CertificateParser;
import it.infn.mw.iam.api.trust.sevice.IamTrustService;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

public class ValidCertificateDTOValidator
        implements ConstraintValidator<ValidCertificateDTO, CertificateDTO> {

    @Autowired
    private X509CertificateParser parser;

    @Autowired
    IamTrustService trustService;

    public ValidCertificateDTOValidator() {
        // empty
    }

    @Override
    public void initialize(ValidCertificateDTO constraintAnnotation) {
        // empty
    }

    private boolean missingPemAndDn(CertificateDTO value) {
        return Strings.isNullOrEmpty(value.getPemEncodedCertificate())
                && (Strings.isNullOrEmpty(value.getSubjectDn())
                        || Strings.isNullOrEmpty(value.getIssuerDn()));
    }

    private boolean inconsistentSubject(CertificateDTO value, IamX509Certificate cert) {
        return !Strings.isNullOrEmpty(value.getSubjectDn())
                && (!X500NameUtils.equal(X500NameUtils.getComparableForm(value.getSubjectDn()),
                        X500NameUtils.getComparableForm(cert.getSubjectDn())));
    }

    private boolean inconsistentIssuer(CertificateDTO value, IamX509Certificate cert) {
        return !Strings.isNullOrEmpty(value.getIssuerDn())
                && (!X500NameUtils.equal(X500NameUtils.getComparableForm(value.getIssuerDn()),
                        X500NameUtils.getComparableForm(cert.getIssuerDn())));
    }

    private boolean unknownCertificationAuthority(CertificateDTO value) throws Exception {
        String issuerDn = value.getIssuerDn();
        if (Strings.isNullOrEmpty(issuerDn)) {
            issuerDn = parser.parseCertificateFromString(value.getPemEncodedCertificate())
                .getIssuerDn();
        }
        return !trustService.getTrusts().getResources().contains(issuerDn);
    }

    @Override
    public boolean isValid(CertificateDTO value, ConstraintValidatorContext context) {

        boolean valid = true;
        try {
            if (value == null) {
                valid = false;
                String message = "Certificate cannot be null.";
                context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
            }
            if (missingPemAndDn(value)) {
                valid = false;
                String message = "Either subject and issuer DN or the PEM content is required. ";
                context.buildConstraintViolationWithTemplate(message).addConstraintViolation();

            }
            if (!Strings.isNullOrEmpty(value.getPemEncodedCertificate())) {
                IamX509Certificate cert =
                        parser.parseCertificateFromString(value.getPemEncodedCertificate());
                if (inconsistentSubject(value, cert)) {
                    valid = false;
                    String message =
                            "When both are provided, the subject of the PEM must be coherent with the subject DN. ";
                    context.buildConstraintViolationWithTemplate(message).addConstraintViolation();

                }
                if (inconsistentIssuer(value, cert)) {
                    valid = false;
                    String message =
                            "When both are provided, the issuer of the PEM must be coherent with the issuer DN. ";
                    context.buildConstraintViolationWithTemplate(message).addConstraintViolation();

                }
            }
            if (unknownCertificationAuthority(value)) {
                valid = false;
                String message = "The selected certification authority is not known to the system.";
                context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
            }
            return valid;
        } catch (Exception e) {
            return false;
        }

    }
}
