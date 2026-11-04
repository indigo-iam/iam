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

import java.io.Serializable;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth 2.0 Protected Resource Metadata, as defined in RFC 9728, Section 2.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ProtectedResourceMetadata(String resource,
    @JsonProperty("authorization_servers") List<String> authorizationServers,
    @JsonProperty("scopes_supported") Set<String> scopesSupported,
    @JsonProperty("bearer_methods_supported") List<String> bearerMethodsSupported,
    @JsonProperty("resource_name") String resourceName,
    @JsonProperty("resource_documentation") String resourceDocumentation,
    @JsonProperty("resource_policy_uri") String resourcePolicyUri,
    @JsonProperty("resource_tos_uri") String resourceTosUri) implements Serializable {

}
