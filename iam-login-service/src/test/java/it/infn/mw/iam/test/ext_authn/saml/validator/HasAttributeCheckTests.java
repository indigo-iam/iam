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
package it.infn.mw.iam.test.ext_authn.saml.validator;

import static it.infn.mw.iam.authn.saml.validator.check.SamlHasAttributeCheck.hasAttribute;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.authn.common.ValidatorResult;

@ExtendWith(MockitoExtension.class)
class HasAttributeCheckTests extends SamlValidatorTestSupport {

  @Test
  void attributeNotFoundIsFailure() {

    ValidatorResult result = hasAttribute(ENTITLEMENT_ATTR_NAME).validate(credential);
    assertThat(result.isFailure(), is(true));
    assertThat(result.hasMessage(), is(true));
    assertThat(result.getMessage(),
        containsString(format("Attribute '%s' not found", ENTITLEMENT_ATTR_NAME)));
  }

  @Test
  void attributeFoundIsSuccess() {

    when(credential.getAttribute(ENTITLEMENT_ATTR_NAME)).thenReturn(attribute);
    ValidatorResult result = hasAttribute(ENTITLEMENT_ATTR_NAME).validate(credential);
    assertThat(result.isSuccess(), is(true));
    assertThat(result.hasMessage(), is(false));
  }

  @Test
  void emptyAttributeNameNotAllowed() {
    assertThrows(IllegalArgumentException.class, () -> hasAttribute(""));
  }

  @Test
  void nullAttributeNameNotAllowed() {
    assertThrows(IllegalArgumentException.class, () -> hasAttribute(null));
  }
}
