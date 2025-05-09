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

public enum ScimFilterAttributes {

    FAMILYNAME("familyname"), GIVENNAME("givenname"), USERNAME("username"), ACTIVE(
            "active"), EMAILS("emails");

    public final String name;

    private ScimFilterAttributes(String name) {
        this.name = name;
    }

    public static ScimFilterAttributes parseAttribute(String attribute) {

        for (ScimFilterAttributes attributes : ScimFilterAttributes.values()) {
            if (attributes.name.equals(attribute)) {
                return attributes;
            }
        }

        throw invalidAttribute(attribute);

    }

    private static IllegalArgumentException invalidAttribute(String attribute) {
        return new IllegalArgumentException(
                String.format("the attribute \"%s\" is not valid within filtering", attribute));
    }


}
