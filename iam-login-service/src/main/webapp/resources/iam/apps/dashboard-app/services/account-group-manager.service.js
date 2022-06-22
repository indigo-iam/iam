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
        .factory('AccountGroupManagerService', AccountGroupManagerService);

    AccountGroupManagerService.$inject = ['$http', '$q'];

    function AccountGroupManagerService($http, $q) {

        var service = {
            getAccountManagedGroups: getAccountManagedGroups,
            addManagedGroupToAccount: addManagedGroupToAccount,
            removeManagedGroupFromAccount: removeManagedGroupFromAccount,
            getGroupManagers: getGroupManagers
        };

        return service;

        function handleSuccess(res) {
            return res.data;
        }

        function handleError(res) {
            return $q.reject(res);
        }

        function getAccountManagedGroups(accountId) {
            return $http.get("/iam/account/" + accountId + "/managed-groups").then(handleSuccess,
                handleError);
        }

        function addManagedGroupToAccount(accountId, groupId) {
            return $http.post("/iam/account/" + accountId + "/managed-groups/" + groupId).then(handleSuccess, handleError);
        }

        function removeManagedGroupFromAccount(accountId, groupId) {
            return $http.delete("/iam/account/" + accountId + "/managed-groups/" + groupId).then(handleSuccess, handleError);
        }

        function getGroupManagers(groupId) {
            return $http.get("/iam/group/" + groupId + "/group-managers").then(handleSuccess, handleError);
        }

    }
})();