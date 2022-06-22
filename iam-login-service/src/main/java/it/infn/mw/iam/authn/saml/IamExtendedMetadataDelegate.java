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
package it.infn.mw.iam.authn.saml;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class IamExtendedMetadataDelegate extends ExtendedMetadataDelegate {

  public IamExtendedMetadataDelegate(MetadataProvider delegate, ExtendedMetadata md) {
    super(delegate, md);
  }

  @Override
  public boolean isTrustFiltersInitialized() {
    return super.isTrustFiltersInitialized();
  }

  @Override
  public void setTrustFiltersInitialized(boolean trustFiltersInitialized) {
    super.setTrustFiltersInitialized(trustFiltersInitialized);
  }

}
