/*
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
(function () {
    'use strict';

    angular
        .module('dashboardApp')
        .service('StringSet', StringSet);

    function StringSet() {

        var service = {
            containsItem: containsItem,
            removeItem: removeItem,
            addItem: addItem
        };

        return service;

        function containsItem(stringSet, item) {
            if (!stringSet || stringSet.length == 0) {
                return false;
            } else {
                var array = stringSet.split(' ');
                return array.indexOf(item) >= 0;
            }
        }

        function removeItem(stringSet, item) {
            if (stringSet && stringSet.length > 0) {
                var array = stringSet.split(' ');
                var index = array.indexOf(item);
                array.splice(index, 1);
                if (array.length > 0) {
                    stringSet = array.sort().join(' ');
                } else {
                    stringSet = "";
                }
            }
            return stringSet;
        }

        function addItem(stringSet, item) {
            var array = [];
            if (stringSet && stringSet.trim().length > 0) {
                array = stringSet.split(' ');
            }
            if (array.indexOf(item) < 0) {
                array.push(item);
                stringSet = array.sort().join(' ');
            }
            return stringSet;
        }
    }

}());