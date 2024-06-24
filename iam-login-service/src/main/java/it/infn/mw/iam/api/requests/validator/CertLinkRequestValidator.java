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

import com.google.common.base.Strings;

import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;

public class CertLinkRequestValidator
        implements ConstraintValidator<CertLinkRequest, CertLinkRequestDTO> {

    public CertLinkRequestValidator() {
        // empty
    }

    @Override
    public void initialize(CertLinkRequest constraintAnnotation) {
        // empty
    }

    @Override
    public boolean isValid(CertLinkRequestDTO value, ConstraintValidatorContext context) {

        try {
            return value != null && (!Strings.isNullOrEmpty(value.getPemEncodedCertificate())
                    || (!Strings.isNullOrEmpty(value.getSubjectDn())
                            && !Strings.isNullOrEmpty(value.getIssuerDn())));
        } catch (Exception e) {
            return false;
        }

    }
}
