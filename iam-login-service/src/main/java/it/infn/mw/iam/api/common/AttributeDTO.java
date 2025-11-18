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

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import it.infn.mw.iam.api.common.validator.NoNewLineOrCarriageReturn;

public record AttributeDTO(

    @Size(max = 64, message = "name cannot be longer than 64 chars") @Pattern(
        regexp = NAME_REGEXP,
        message = "invalid name (does not match with regexp: '" + NAME_REGEXP
            + "')") @NotBlank String name,

    @Size(max = 256,
        message = "value cannot be longer than 256 chars") @NoNewLineOrCarriageReturn String value

) {
  public static final String NAME_REGEXP = "^[a-zA-Z][a-zA-Z0-9\\-_.]*$";
}
