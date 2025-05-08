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

package it.infn.mw.iam.api.scim.model;

import it.infn.mw.iam.api.scim.provisioning.model.ScimFilterAttributes;
import it.infn.mw.iam.api.scim.provisioning.model.ScimFilterOperators;

public class ScimFilter {

    private final ScimFilterAttributes attribute;

    private final ScimFilterOperators operator;

    private final String value;


    public ScimFilter(ScimFilterAttributes attribute, ScimFilterOperators operator, String value) {
        this.attribute = attribute;
        this.operator = operator;
        this.value = value;
    }


    public ScimFilterAttributes getAttribute() {
        return this.attribute;
    }

    public ScimFilterOperators getOperator() {
        return this.operator;
    }

    public String getValue() {
        return this.value;
    }



}
