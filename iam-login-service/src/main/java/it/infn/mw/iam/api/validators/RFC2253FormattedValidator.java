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

import static eu.emi.security.authn.x509.impl.X500NameUtils.getPortableRFC2253Form;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

@Component
@Scope("prototype")
public class RFC2253FormattedValidator implements ConstraintValidator<RFC2253Formatted, String> {

    public RFC2253FormattedValidator() {
        // Empty on purpose
    }

    @Override
    public void initialize(RFC2253Formatted constraintAnnotation) {
        // Empty on purpose
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        try {
            getPortableRFC2253Form(value);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

}
