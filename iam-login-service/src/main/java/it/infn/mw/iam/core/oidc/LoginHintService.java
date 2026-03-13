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
package it.infn.mw.iam.core.oidc;

import static org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_HINT;

import java.util.Map;

import javax.servlet.http.HttpSession;

import org.mitre.openid.connect.service.LoginHintExtracter;
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

@Service
public class LoginHintService {

  private LoginHintExtracter loginHintExtracter = new RemoveLoginHintsWithHTTP();

  public void handleLoginHint(Map<String, String> params, HttpSession session) {

    String loginHint = loginHintExtracter.extractHint(params.get(LOGIN_HINT));

    if (!Strings.isNullOrEmpty(loginHint)) {
      session.setAttribute(LOGIN_HINT, loginHint);
    } else {
      session.removeAttribute(LOGIN_HINT);
    }
  }
}
