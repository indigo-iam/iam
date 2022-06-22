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
(function() {
    'use strict';

    angular.module('dashboardApp')
        .factory('AupService', AupService);

    AupService.$inject = ['$http', '$q'];

    function AupService($http, $q) {

        var service = {
            getAup: getAup,
            createAup: createAup,
            updateAup: updateAup,
            touchAup: touchAup,
            deleteAup: deleteAup,
            getAupSignature: getAupSignature,
            getAupSignatureForUser: getAupSignatureForUser
        };

        return service;

        function deleteAup() {
            return $http.delete('/iam/aup');
        }

        function createAup(aup) {
            return $http.post('/iam/aup', aup);
        }

        function updateAup(aup) {
            return $http.patch('/iam/aup', aup);
        }

        function touchAup() {
            return $http.post('/iam/aup/touch');
        }

        function getAupSignatureForUser(userId) {
            return $http.get('/iam/aup/signature/' + userId).catch(function(res) {
                if (res.status == 404) {
                    console.info("AUP signature not found");
                    return null;
                }
                return $q.reject(res);
            });
        }

        function getAupSignature() {
            return $http.get('/iam/aup/signature').catch(function(res) {
                if (res.status == 404) {
                    console.info("AUP signature not found");
                    return null;
                }
                return $q.reject(res);
            });
        }

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
})();