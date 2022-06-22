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
package it.infn.mw.iam.core.web;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class IamRootController {

  @RequestMapping(method = RequestMethod.GET, path = {"", "home", "index"})
  public String home(Authentication authentication) {

    if (authentication.getAuthorities().contains(EXT_AUTHN_UNREGISTERED_USER_AUTH)) {
      return "forward:/start-registration";
    }
    return "home";
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = "manage/**")
  public String manage(ModelMap m) {
    return "manage";
  }

  @RequestMapping(method = RequestMethod.GET, path = "/login")
  public String login(Authentication authentication, Model model, HttpServletRequest request) {

    if (authentication == null) {
      return "iam/login";
    }

    if (authentication.getAuthorities().contains(EXT_AUTHN_UNREGISTERED_USER_AUTH)) {
      return "forward:/start-registration";
    }

    return "redirect:/";

  }

  @RequestMapping(method = RequestMethod.GET, path = "/reset-session")
  public String resetSession(HttpSession session) {

    SecurityContextHolder.clearContext();
    session.invalidate();

    return "redirect:/";
  }
}
