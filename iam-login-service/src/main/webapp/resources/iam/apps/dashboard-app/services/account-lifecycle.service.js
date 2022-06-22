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

    angular.module('dashboardApp')
        .factory('AccountLifecycleService', AccountLifecycleService);

    AccountLifecycleService.$inject = ['$http', '$q'];

    function AccountLifecycleService($http, $q) {

        var service = {
            setAccountEndTime: setAccountEndTime,
            readOnlyAccountEndTime: readOnlyAccountEndTime
        };

        return service;

        function handleSuccess(res) {
            return res.data;
        }

        function handleError(res) {
            return $q.reject(res);
        }

        function readOnlyAccountEndTime() {

            return $http.get("/iam/config/lifecycle/account/read-only-end-time", {
                cache: true
            }).then(handleSuccess, handleError);
        }

        function setAccountEndTime(accountId, endTime) {

            var config = {
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
            };

            var dto = {
                "endTime": endTime
            };

            return $http.put("/iam/account/" + accountId + "/endTime", dto, config).then(handleSuccess, handleError);
        }

    }

})();