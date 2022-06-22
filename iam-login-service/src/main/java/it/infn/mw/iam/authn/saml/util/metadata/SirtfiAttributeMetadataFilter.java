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
package it.infn.mw.iam.authn.saml.util.metadata;

import java.util.Arrays;

public class SirtfiAttributeMetadataFilter extends AttributeValueMetadataFilter {

  public static final String ASSURANCE_CERTIFICATION_ATTRIBUTE_NAME =
      "urn:oasis:names:tc:SAML:attribute:assurance-certification";

  public static final String SIRTFI_ATTRIBUTE_VALUE = "https://refeds.org/sirtfi";

  public SirtfiAttributeMetadataFilter() {
    super(ASSURANCE_CERTIFICATION_ATTRIBUTE_NAME, Arrays.asList(SIRTFI_ATTRIBUTE_VALUE));
  }

}
