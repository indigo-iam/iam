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
package it.infn.mw.iam.audit.events.tokens;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.IamEventCategory;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;

public class RevocationEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -1843180591267883819L;

  private final String jwtId;
  private final TokenTypeHint tokenTypeHint;

  public RevocationEvent(Object source, String jwtId, TokenTypeHint tokenTypeHint) {

    super(IamEventCategory.TOKEN, source, "Token revocation request");
    this.jwtId = jwtId;
    this.tokenTypeHint = tokenTypeHint;
  }

  public String getJwtId() {
    return jwtId;
  }

  public TokenTypeHint getTokenTypeHint() {
    return tokenTypeHint;
  }

}
