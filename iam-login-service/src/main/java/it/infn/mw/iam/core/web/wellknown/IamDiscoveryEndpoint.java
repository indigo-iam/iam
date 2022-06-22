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

import org.mitre.discovery.util.WebfingerURLNormalizer;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.JsonEntityView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.base.Strings;

@Controller
public class IamDiscoveryEndpoint {

  private static final Logger LOG = LoggerFactory.getLogger(IamDiscoveryEndpoint.class);

  private static final String WELL_KNOWN_URL = ".well-known";
  public static final String OPENID_CONFIGURATION_URL = WELL_KNOWN_URL + "/openid-configuration";
  private static final String WEBFINGER_URL = WELL_KNOWN_URL + "/webfinger";

  private final ConfigurationPropertiesBean config;
  private final UserInfoService userService;
  private final WellKnownInfoProvider wellKnownInfoProvider;

  @Autowired
  public IamDiscoveryEndpoint(ConfigurationPropertiesBean config, UserInfoService userService,
      WellKnownInfoProvider wellKnownInfoProvider) {
    this.config = config;
    this.userService = userService;
    this.wellKnownInfoProvider = wellKnownInfoProvider;
  }

  @RequestMapping(value = {"/" + WEBFINGER_URL}, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
  public String webfinger(@RequestParam("resource") String resource,
      @RequestParam(value = "rel", required = false) String rel, Model model) {

    if (!Strings.isNullOrEmpty(rel) && !"http://openid.net/specs/connect/1.0/issuer".equals(rel)) {
      LOG.warn("Responding to webfinger request for non-OIDC relation: {}", rel);
    }

    if (!resource.equals(config.getIssuer())) {
      // it's not the issuer directly, need to check other methods

      UriComponents resourceUri = WebfingerURLNormalizer.normalizeResource(resource);
      if (resourceUri != null && resourceUri.getScheme() != null
          && "acct".equals(resourceUri.getScheme())) {
        // acct: URI (email address format)

        // check on email addresses first
        UserInfo user =
            userService.getByEmailAddress(resourceUri.getUserInfo() + "@" + resourceUri.getHost());

        if (user == null) {
          // user wasn't found, see if the local part of the username matches, plus our issuer iamHost

          user = userService.getByUsername(resourceUri.getUserInfo()); // first part is the username

          if (user != null) {
            // username matched, check the iamHost component
            UriComponents issuerComponents =
                UriComponentsBuilder.fromHttpUrl(config.getIssuer()).build();
            if (!Strings.nullToEmpty(issuerComponents.getHost())
              .equals(Strings.nullToEmpty(resourceUri.getHost()))) {
              LOG.info("Host mismatch, expected {} got {}", issuerComponents.getHost(),
                  resourceUri.getHost());
              model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
              return HttpCodeView.VIEWNAME;
            }

          } else {
            LOG.info("User not found: {}", resource);
            model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
            return HttpCodeView.VIEWNAME;
          }

        }

      } else {
        LOG.info("Unknown URI format: {}", resource);
        model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
        return HttpCodeView.VIEWNAME;
      }
    }

    model.addAttribute("resource", resource);
    model.addAttribute("issuer", config.getIssuer());

    return "webfingerView";
  }

  @RequestMapping(value = {"/" + OPENID_CONFIGURATION_URL}, method = RequestMethod.GET)
  public String providerConfiguration(Model model) {
    model.addAttribute(JsonEntityView.ENTITY, wellKnownInfoProvider.getWellKnownInfo());
    return JsonEntityView.VIEWNAME;
  }
}
