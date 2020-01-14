/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
'use strict';

angular.module('registrationApp').factory('Aup', Aup);

Aup.$inject = ['$http', '$q'];

function Aup($http, $q) {

    var service = {
        getAup: getAup
    };

    return service;

    function getAup() {
        return $http.get('/iam/aup').catch(function(res) {
            if (res.status == 404) {
                console.info("AUP not defined");
                return null;
            }
            return $q.reject(res);
        });
    }
}