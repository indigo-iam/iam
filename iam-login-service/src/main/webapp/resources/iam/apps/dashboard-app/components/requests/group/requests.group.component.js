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

    function RejectRequest($uibModalInstance, GroupRequestsService, toaster, request, userFullName) {
        var self = this;

        self.request = request;
        self.userFullName = userFullName;
        self.motivation;

        self.cancel = function() {
            $uibModalInstance.dismiss('Dismissed');
        };

        self.reject = function() {
            GroupRequestsService.rejectRequest(self.request, self.motivation).then(function(r) {
                $uibModalInstance.close(r);
            }).catch(function(r) {
                toaster.pop({
                    type: 'error',
                    body: r.statusText
                });
            });
        };
    }

    function GroupRequestsController($scope, $rootScope, $uibModal, Utils, GroupRequestsService, $filter, filterFilter, toaster) {
        var self = this;
        self.loaded = false;
        self.filter = "";
        self.filtered = [];
        self.busy = false;
        self.itemsPerPage = 10;
        self.currentPage = 1;
        self.voAdmin = Utils.isAdmin();

        $scope.$watch('$ctrl.filter', function() {
            self.currentPage = 1;
            filterRequests(1);
        });

        self.groupManagerForGroup = function(req) {
            return Utils.isGroupManagerForGroup(req.groupUuid);
        };

        function updatePageCounters() {
            self.pageLeft = ((self.currentPage - 1) * self.itemsPerPage) + 1;
            self.pageRight = Math.min(self.currentPage * self.itemsPerPage, self.totalResults);
        }

        function updateRootScopeCounters(res) {
            $rootScope.pendingGroupMembershipRequests(res);
        }

        function errorHandler(res) {
            toaster.pop({
                type: 'error',
                body: res.statusText
            });
        }

        function loadSuccess(res, updateRootCounters = true) {
            self.totalResults = res.totalResults;
            updatePageCounters();
            if (updateRootCounters) {
                updateRootScopeCounters(res);
                self.filtered = self.requests = res.Resources;
            } else {
                self.filtered = res.Resources;
            }
            self.loaded = true;
            self.busy = false;
            return res;
        }

        function loadRequests(page) {
            return GroupRequestsService.getGroupRequests({ status: 'PENDING', startIndex: page }).then(loadSuccess, errorHandler);
        }

        self.$onInit = function() {
            self.api = {};
            self.api.load = loadRequests;
            self.parentCb({ $API: self.api });
            loadRequests();
        };

        function filterRequests(startIndex) {
            const filterPayload = {
                status: 'PENDING',
                startIndex: startIndex,
                username: self.filter,
                userFullName: self.filter,
                groupName: self.filter,
                notes: self.filter
            };

            GroupRequestsService.searchGroupRequests(filterPayload)
                .then(response => loadSuccess(response, false))
                .catch(errorHandler);
        }

        self.resetFilter = function() {
            self.filter = "";
        }

        self.approve = function(req) {
            self.busy = true;
            return GroupRequestsService.approveRequest(req).then(approveSuccess, decisionErrorHandler);
        };

        self.reject = function(req) {
            var modal = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/requests/reject-request.dialog.html',
                controller: RejectRequest,
                controllerAs: '$ctrl',
                resolve: {
                    request: req,
                    userFullName: function() {
                        return req.userFullName;
                    }
                }
            });

            modal.result.then(rejectSuccess, decisionErrorHandler);
        };

        function approveSuccess(res) {
            var startIndex = ((self.currentPage - 1) * self.itemsPerPage) + 1;

            loadRequests().then(() => {
                if (self.filter && self.filter.trim() !== "") {
                    return filterRequests(startIndex);
                }
            }).then(() => {
                toaster.pop({
                    type: 'success',
                    body: "Request approved"
                });
            }).catch(errorHandler);
        }

        function rejectSuccess(res) {
            var startIndex = ((self.currentPage - 1) * self.itemsPerPage) + 1;

            loadRequests().then(() => {
                if (self.filter && self.filter.trim() !== "") {
                    return filterRequests(startIndex);
                }
            }).then(() => {
                toaster.pop({
                    type: 'success',
                    body: "Request rejected"
                });
            }).catch(errorHandler);
        }

        function decisionErrorHandler(res) {
            if (!res === 'Dismissed') {
                toaster.pop({
                    type: 'error',
                    body: res.statusText
                });
            }
            self.busy = false;
        }

        self.pageChanged = function () {
            var startIndex = ((self.currentPage - 1) * self.itemsPerPage) + 1;
            if (self.filter) {
                filterRequests(startIndex);
            } else {
                loadRequests(startIndex).then(function (r) {
                    console.log(r);
                });
            }
        };
    }


    angular
        .module('dashboardApp')
        .component('groupRequests', groupRequests());

    function groupRequests() {
        return {
            bindings: {
                parentCb: '&'
            },
            templateUrl: '/resources/iam/apps/dashboard-app/components/requests/group/requests.group.component.html',
            controller: ['$scope', '$rootScope', '$uibModal', 'Utils', 'GroupRequestsService', '$filter', 'filterFilter', 'toaster', GroupRequestsController],
            controllerAs: '$ctrl'
        };
    }

}());