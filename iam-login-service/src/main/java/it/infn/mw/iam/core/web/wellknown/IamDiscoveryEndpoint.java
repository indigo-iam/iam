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
package it.infn.mw.iam.core.web.wellknown;

import org.mitre.openid.connect.view.JsonEntityView;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IamDiscoveryEndpoint {

  private static final String WELL_KNOWN_URL = ".well-known";
  public static final String OPENID_CONFIGURATION_URL = WELL_KNOWN_URL + "/openid-configuration";

  private final WellKnownInfoProvider wellKnownInfoProvider;

  public IamDiscoveryEndpoint(WellKnownInfoProvider wellKnownInfoProvider) {
    this.wellKnownInfoProvider = wellKnownInfoProvider;
  }

  @GetMapping(value = {"/" + OPENID_CONFIGURATION_URL})
  public String providerConfiguration(Model model) {
    model.addAttribute(JsonEntityView.ENTITY, wellKnownInfoProvider.getWellKnownInfo());
    return JsonEntityView.VIEWNAME;
  }
}
