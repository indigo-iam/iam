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

    function GroupRequestsController($scope, $rootScope, $uibModal, GroupRequestsService, $filter, filterFilter, toaster) {
        var self = this;
        self.loaded = false;
        self.filter = "";
        self.filtered = [];
        self.busy = false;
        self.itemsPerPage = 10;
        self.currentPage = 1;

        $scope.$watch('$ctrl.filter', function() {
            filterRequests();
        });

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

        function loadSuccess(res) {
            self.totalResults = res.totalResults;
            self.filtered = self.requests = res.Resources;
            updatePageCounters();
            updateRootScopeCounters(res);
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

        function filterRequests() {
            self.filtered = filterFilter(self.requests, function(request) {

                if (!self.filter) {
                    return true;
                }

                var query = self.filter.toLowerCase();

                if (request.userFullName.toLowerCase().indexOf(query) != -1) {
                    return true;
                }
                if (request.username.toLowerCase().indexOf(query) != -1) {
                    return true;
                }
                if (request.groupName.toLowerCase().indexOf(query) != -1) {
                    return true;
                }

                if (request.notes.toLowerCase().indexOf(query) != -1) {
                    return true;
                }
                return false;
            });

            if (self.filtered) {
                updatePageCounters();
            }
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
            loadRequests().then(function(res) {
                toaster.pop({
                    type: 'success',
                    body: "Request approved"
                });
            });
        }

        function rejectSuccess(res) {
            loadRequests().then(function(res) {
                toaster.pop({
                    type: 'success',
                    body: "Request rejected"
                });
            });
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

        self.pageChanged = function() {
            var startIndex = ((self.currentPage - 1) * self.itemsPerPage) + 1;
            loadRequests(startIndex).then(function(r) {
                console.log(r);
            });
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
            controller: ['$scope', '$rootScope', '$uibModal', 'GroupRequestsService', '$filter', 'filterFilter', 'toaster', GroupRequestsController],
            controllerAs: '$ctrl'
        };
    }

}());