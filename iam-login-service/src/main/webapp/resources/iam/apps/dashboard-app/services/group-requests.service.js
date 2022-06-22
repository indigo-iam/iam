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

    angular.module('dashboardApp').factory('GroupRequestsService', GroupRequestsService);

    GroupRequestsService.$inject = ['$q', '$http', 'Utils'];

    function GroupRequestsService($q, $http, Utils) {

        var service = {
            getGroupRequests: getGroupRequests,
            getAllPendingGroupRequestsForUser: getAllPendingGroupRequestsForUser,
            getAllPendingGroupRequestsForAuthenticatedUser: getAllPendingGroupRequestsForAuthenticatedUser,
            submit: submit,
            abortRequest: abortRequest,
            rejectRequest: rejectRequest,
            approveRequest: approveRequest
        };

        return service;

        function abortRequest(req) {
            return $http.delete("/iam/group_requests/" + req.uuid);
        }

        function rejectRequest(req, m) {
            return $http.post("/iam/group_requests/" + req.uuid + "/reject?motivation=" + m);
        }

        function approveRequest(req) {
            return $http.post("/iam/group_requests/" + req.uuid + "/approve");
        }

        function submit(req) {
            return $http.post("/iam/group_requests", req);
        }

        function getAllPendingGroupRequestsForAuthenticatedUser() {
            return getAllPendingGroupRequestsForUser(Utils.username());
        }

        function getAllPendingGroupRequestsForUser(username) {

            var p = {
                username: username,
                status: 'PENDING'
            };

            return getGroupRequests(p).then(function(res) {
                var totalResults = res.totalResults;
                if (res.totalResults == res.itemsPerPage) {
                    return res.Resources;
                } else {

                    var results = res.Resources;
                    var promises = [];

                    var numCalls = Math.floor(res.totalResults / res.itemsPerPage);

                    if (res.totalResults % res.itemsPerPage > 0) {
                        numCalls = numCalls + 1;
                    }

                    var appendResults = function(sc) {
                        results = results.concat(sc.Resources);
                    };

                    for (var i = 1; i < numCalls; i++) {
                        var startIndex = i * res.itemsPerPage + 1;
                        p.startIndex = startIndex;
                        promises.push(getGroupRequests(p).then(appendResults));
                    }

                    return $q.all(promises).then(function(res) {
                        return results;
                    });
                }
            });
        }

        function getGroupRequests(params) {
            return $http.get("/iam/group_requests", {
                params: params
            }).then(function(res) {
                return res.data;
            }).catch(function(res) {
                return $q.reject(res);
            });
        }
    }

})();