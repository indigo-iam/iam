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
        .service('FindService', FindService);


    FindService.$inject = ['$q', '$http'];

    function FindService($q, $http) {

        var service = {
            findUnsubscribedGroupsForAccount: findUnsubscribedGroupsForAccount
        };

        return service;

        function findUnsubscribedGroupsForAccount(accountId, nameFilter, startIndex, count) {
            var url = "/iam/group/find/unsubscribed/" + accountId;
            return $http.get(url, {
                params: {
                    'filter': nameFilter,
                    'startIndex': startIndex,
                    'count': count
                }
            }).then(function (result) {
                return result.data;
            }).catch(function (error) {
                console.error("Error loading group members: ", error);
                return $q.reject(error);
            });
        }
    }
}());