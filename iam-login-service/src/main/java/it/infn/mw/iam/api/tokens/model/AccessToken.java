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
package it.infn.mw.iam.api.tokens.model;

import java.util.Date;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonFilter("attributeFilter")
public record AccessToken(
    @JsonProperty("id") Long id,
    @JsonProperty("audiences") Set<String> audiences,
    @JsonProperty("scopes") Set<String> scopes,
    @JsonProperty("expiration") Date expiration,
    @JsonProperty("clientId") String clientId,
    @JsonProperty("client") ClientRef client,
    @JsonProperty("user") UserRef user,
    @JsonProperty("refreshTokenId") Long refreshTokenId
) {}
