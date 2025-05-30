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
package it.infn.mw.iam.api.scim.provisioning.model;

public enum ScimFilterOperators {

    EQUALS("eq"), CONTAINS("co");

    public final String type;

    private ScimFilterOperators(String type) {
        this.type = type;
    }

    public static ScimFilterOperators parseOperator(String operator) {

        for (ScimFilterOperators operators : ScimFilterOperators.values()) {
            if (operators.type.equals(operator)) {
                return operators;
            }
        }

        throw invalidOperator(operator);

    }


    private static IllegalArgumentException invalidOperator(String operator) {
        return new IllegalArgumentException(String.format(
                "the operator \"%s\" can not be used with the given filtering attribute",
                operator));
    }


}
