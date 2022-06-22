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
package it.infn.mw.iam.api.common;

public class NoSuchAccountError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = -7259771093968890099L;

  public NoSuchAccountError(String message) {
    super(message);

  }
  
  public static final NoSuchAccountError forUuid(String uuid) {
    return new NoSuchAccountError(String.format("Account not found for id '%s'", uuid));
  }
  
  public static final NoSuchAccountError forUsername(String username) {
    return new NoSuchAccountError(String.format("Account not found for username '%s'", username));
  }
}
