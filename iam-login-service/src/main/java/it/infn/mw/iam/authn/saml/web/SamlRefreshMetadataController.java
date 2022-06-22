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
package it.infn.mw.iam.authn.saml.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.authn.saml.MetadataLookupService;

@RestController
@Profile("saml")
public class SamlRefreshMetadataController {
  
  @Autowired
  MetadataManager metadataManager;
  
  @Autowired
  MetadataLookupService metadataLookupService;

  @PreAuthorize("hasRole('ADMIN')")
  @RequestMapping(value="/saml/refresh-metadata", method = RequestMethod.GET)
  public String refreshMetadata() {
    metadataManager.setRefreshRequired(true);
    metadataManager.refreshMetadata();
    metadataLookupService.refreshMetadata();
    return "ok";
  }

}
