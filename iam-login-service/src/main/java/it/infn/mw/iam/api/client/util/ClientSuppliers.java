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
package it.infn.mw.iam.api.client.util;

import java.util.function.Supplier;

import it.infn.mw.iam.api.client.error.InvalidPaginationRequest;
import it.infn.mw.iam.api.client.error.NoSuchClient;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;

public class ClientSuppliers {

  private static final String CLIENT_NOT_FOUND_ERROR_STR = "Client not found for clientId: %s";
  private static final String ACCOUNT_NOT_FOUND_ERROR_STR = "Account not found for id: %s";



  private ClientSuppliers() {
    // do not instantiate
  }

  public static Supplier<NoSuchClient> clientNotFound(String clientId) {
    return () -> new NoSuchClient(String.format(CLIENT_NOT_FOUND_ERROR_STR, clientId));
  }

  public static Supplier<InvalidPaginationRequest> invalidPaginationRequest(String message) {
    return () -> new InvalidPaginationRequest(message);
  }

  public static Supplier<NoSuchAccountError> accountNotFound(String accountId) {
    return () -> new NoSuchAccountError(String.format(ACCOUNT_NOT_FOUND_ERROR_STR, accountId));
  }

}
