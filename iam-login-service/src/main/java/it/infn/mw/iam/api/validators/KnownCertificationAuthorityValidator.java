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

import static eu.emi.security.authn.x509.impl.X500NameUtils.equal;

import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.trust.sevice.IamTrustService;

@Component
@Scope("prototype")
public class KnownCertificationAuthorityValidator
        implements ConstraintValidator<KnownCertificationAuthority, String> {

    @Autowired
    IamTrustService trustService;

    public KnownCertificationAuthorityValidator() {
        // Empty on purpose
    }

    @Override
    public void initialize(KnownCertificationAuthority constraintAnnotation) {
        // Empty on purpose
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (Strings.isNullOrEmpty(value))
            return true;
        try {
            List<String> knownCertificationAuthorities = trustService.getTrusts().getResources();
            return knownCertificationAuthorities.stream().anyMatch(ca -> equal(ca, value));
        } catch (Exception e) {
            return false;
        }
    }

}
