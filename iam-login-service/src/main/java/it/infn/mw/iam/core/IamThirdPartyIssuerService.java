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
package it.infn.mw.iam.core;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.mitre.openid.connect.client.model.IssuerServiceResponse;
import org.mitre.openid.connect.client.service.IssuerService;
import org.springframework.security.authentication.AuthenticationServiceException;

public class IamThirdPartyIssuerService implements IssuerService {

  private Set<String> blacklist = new HashSet<>();
  private Set<String> whitelist = new HashSet<>();

  @Override
  public IssuerServiceResponse getIssuer(HttpServletRequest request) {
    // if the issuer is passed in, return that
    String iss = request.getParameter("iss");

    if (!whitelist.isEmpty() && !whitelist.contains(iss)) {
      throw new AuthenticationServiceException(
          "Whitelist was nonempty, issuer was not in whitelist: " + iss);
    }

    if (blacklist.contains(iss)) {
      throw new AuthenticationServiceException("Issuer was in blacklist: " + iss);
    }

    return new IssuerServiceResponse(iss, request.getParameter("login_hint"),
        request.getParameter("target_link_uri"));
  }

  public Set<String> getBlacklist() {
    return blacklist;
  }

  public void setBlacklist(Set<String> blacklist) {
    this.blacklist = blacklist;
  }

  public Set<String> getWhitelist() {
    return whitelist;
  }

  public void setWhitelist(Set<String> whitelist) {
    this.whitelist = whitelist;
  }
}
