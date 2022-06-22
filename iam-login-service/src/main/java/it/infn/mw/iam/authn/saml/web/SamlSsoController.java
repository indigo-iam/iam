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

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import it.infn.mw.iam.authn.saml.MetadataLookupService;
import it.infn.mw.iam.authn.saml.model.IdpDescription;

@Controller
@RequestMapping("/saml")
@Profile("saml")
public class SamlSsoController {

  public static final Logger LOG = LoggerFactory.getLogger(SamlSsoController.class);

  @Autowired
  MetadataLookupService lookupService;
  
  @RequestMapping(value = "/idps", method = RequestMethod.GET)
  public @ResponseBody List<IdpDescription> idps(
      @RequestParam(value = "q", required = false) String text) {

    if (text == null) {
      return lookupService.listIdps().stream().limit(20).collect(Collectors.toList());
    }

    return lookupService.lookupIdp(text);
  }


  @RequestMapping(value = "/discovery", method = RequestMethod.GET)
  public String selectIdp(@RequestParam("entityID") String entityId,
      @RequestParam("returnIDParam") String returnIDParam) {
    return "iam/samlDiscovery";
  }
  
}
