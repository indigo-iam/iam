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

    angular.module('dashboardApp').factory('RegistrationRequestService', RegistrationRequestService);

    RegistrationRequestService.$inject = ['$http', '$q', '$httpParamSerializerJQLike'];

    function RegistrationRequestService($http, $q, $httpParamSerializerJQLike) {

        var service = {
            createRequest: createRequest,
            listRequests: listRequests,
            listPending: listPending,
            approveRequest: approveRequest,
            rejectRequest: rejectRequest,
            bulkApprove: bulkApprove,
            bulkReject: bulkReject
        };

        return service;

        function createRequest(request) {
            var config = {
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
            };
            return $http.post('/registration/create', request, config);
        }

        function listRequests(status) {
            return $http.get('/registration/list', {
                params: {
                    status: status
                }
            });
        }

        function listPending() {
            return $http.get('/registration/list/pending');
        }

        function approveRequest(req) {
            return $http.post('/registration/approve/' + req.uuid);
        }

        function rejectRequest(req, motivation) {

            var d = {
                motivation: motivation
            };

            return $http({
                url: '/registration/reject/' + req.uuid,
                method: 'POST',
                data: $httpParamSerializerJQLike(d),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });
        }

        function bulkApprove(requests) {
            var promises = [];
            angular.forEach(requests, r => promises.push(approveRequest(r)));
            return $q.all(promises);
        }

        function bulkReject(requests, motivation) {
            var promises = [];
            angular.forEach(requests, r => promises.push(rejectRequest(r, motivation)));
            return $q.all(promises);
        }
    }
})();