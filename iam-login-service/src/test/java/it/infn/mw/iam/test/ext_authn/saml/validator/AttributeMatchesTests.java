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

import static it.infn.mw.iam.authn.saml.validator.check.SamlAttributeValueRegexpMatch.attrValueMatches;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.common.ValidatorResult;

@RunWith(MockitoJUnitRunner.class)
public class AttributeMatchesTests extends SamlValidatorTestSupport {

  @Test
  public void attributeNotFoundIsFailure() {

    ValidatorResult result = attrValueMatches(ENTITLEMENT_ATTR_NAME, ".*").validate(credential);
    assertThat(result.isFailure(), is(true));
    assertThat(result.hasMessage(), is(true));
    assertThat(result.getMessage(), containsString((format("Attribute '%s' not found", ENTITLEMENT_ATTR_NAME))));
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullAttributeNameNotAllowed() {
    attrValueMatches(null, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullRegexpNotAllowed() {
    attrValueMatches(ENTITLEMENT_ATTR_NAME, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void emptyAttributeNameNotAllowed() {
    attrValueMatches("", ".*");
  }

  @Test(expected = IllegalArgumentException.class)
  public void emptyRegexpNotAllowed() {
    attrValueMatches(ENTITLEMENT_ATTR_NAME, "");
  }

  @Test
  public void simpleMatch() {
    when(credential.getAttribute(ENTITLEMENT_ATTR_NAME)).thenReturn(attribute);
    when(credential.getAttributeAsStringArray(ENTITLEMENT_ATTR_NAME))
      .thenReturn(new String[] {"example"});
    ValidatorResult result =
        attrValueMatches(ENTITLEMENT_ATTR_NAME, "that|example").validate(credential);
    assertThat(result.isSuccess(), is(true));
    assertThat(result.hasMessage(), is(false));
  }

  @Test
  public void multiMatch() {
    when(credential.getAttribute(ENTITLEMENT_ATTR_NAME)).thenReturn(attribute);
    when(credential.getAttributeAsStringArray(ENTITLEMENT_ATTR_NAME))
      .thenReturn(new String[] {"one", "two", "three", "that"});
    ValidatorResult result =
        attrValueMatches(ENTITLEMENT_ATTR_NAME, "that|example").validate(credential);
    assertThat(result.isSuccess(), is(true));
    assertThat(result.hasMessage(), is(false));
  }

  @Test
  public void noMatch() {
    when(credential.getAttribute(ENTITLEMENT_ATTR_NAME)).thenReturn(attribute);
    when(credential.getAttributeAsStringArray(ENTITLEMENT_ATTR_NAME))
      .thenReturn(new String[] {"example"});
    ValidatorResult result =
        attrValueMatches(ENTITLEMENT_ATTR_NAME, "wont_match").validate(credential);

    assertThat(result.isFailure(), is(true));
    assertThat(result.hasMessage(), is(true));
    assertThat(result.getMessage(), containsString(format("No attribute '%s' value found matching regexp: '%s'",
        ENTITLEMENT_ATTR_NAME, "wont_match")));
  }

}
