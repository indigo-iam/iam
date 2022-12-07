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

    angular.module('dashboardApp').factory('PoliciesService', PoliciesService);

    PoliciesService.$inject = ['$q', '$http', '$httpParamSerializer'];

    function PoliciesService($q, $http, $httpParamSerializer) {
        var service = {
            getAllPolicies: getAllPolicies,
            updatePolicyById: updatePolicyById,
            addPolicy: addPolicy,
            removePolicy: removePolicy
        };

        var urlScopePolicies = "/iam/scope_policies/";

        return service;

        function doGet() {
            return $http.get(urlScopePolicies);
        }

        function doGetPolicyById(policy) {
            return $http.get(urlScopePolicies + policy.id );
        }

        function doPut(policy) {
            return $http.put(urlScopePolicies + policy.id, policy );
        }

        function doDelete(policy) {
            return $http.delete(urlScopePolicies + policy.id );
        }

        function doPost(data) {
            return $http.post(urlScopePolicies, data);
        }

        function getAllPolicies() {
            console.debug("Getting All scope policies... ");
            return doGet();
        }

        function updatePolicyById(policy) {
            console.debug("updatePolicyById: ", policy.id, policy.value);
            return doPut(policy);
        }

        function addPolicy(policy) {
            console.debug("addPolicy: ", policy.id, policy.value);
            return doPost(policy);
        }

        function removePolicy(policy) {
            console.debug("removePolicy: ", policy.id, policy.value)
            return doDelete(policy);
        }



    }
})();