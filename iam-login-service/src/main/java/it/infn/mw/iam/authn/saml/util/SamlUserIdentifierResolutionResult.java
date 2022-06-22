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
package it.infn.mw.iam.authn.saml.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import it.infn.mw.iam.persistence.model.IamSamlId;

public class SamlUserIdentifierResolutionResult {
  
  
  final Optional<IamSamlId> resolvedId;
  final Optional<List<String>> errorMessages;
  
  private SamlUserIdentifierResolutionResult(IamSamlId resolvedId){
    this.resolvedId = Optional.of(resolvedId);
    this.errorMessages = Optional.empty();
  }
  
  private SamlUserIdentifierResolutionResult(String errorMessage){
    this.resolvedId = Optional.empty();
    List<String> errors = new ArrayList<>();
    errors.add(errorMessage);
    this.errorMessages = Optional.of(errors);
  }
  
  private SamlUserIdentifierResolutionResult(List<String> errorMessages){
    this.resolvedId = Optional.empty();
    this.errorMessages = Optional.of(errorMessages);
  }

  public Optional<IamSamlId> getResolvedId() {
    return resolvedId;
  }
  
  public Optional<List<String>> getErrorMessages() {
    return errorMessages;
  }

  public static SamlUserIdentifierResolutionResult resolutionSuccess(IamSamlId resolvedId){
    return new SamlUserIdentifierResolutionResult(resolvedId);
  }
  
  public static SamlUserIdentifierResolutionResult resolutionFailure(String errorMessage){
    return new SamlUserIdentifierResolutionResult(errorMessage);
  }
  
  public static SamlUserIdentifierResolutionResult resolutionFailure(List<String> errorMessages) {
    return new SamlUserIdentifierResolutionResult(errorMessages);
  }
}
