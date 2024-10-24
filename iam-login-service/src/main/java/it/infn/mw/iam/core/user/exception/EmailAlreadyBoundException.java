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
package it.infn.mw.iam.core.user.exception;

import static java.lang.String.format;

public class EmailAlreadyBoundException extends IamAccountException {

  /**
   * 
   */
  private static final long serialVersionUID = 4103663720620113509L;

  public EmailAlreadyBoundException(String email, String targetUser, String emailOwner) {
    super(format(
        "Unable to set email '%s' to user '%s': email already bounded to another user ('%s')",
        email, targetUser, emailOwner));
  }

}
