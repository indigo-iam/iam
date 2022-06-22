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
        .component('userPendingRequests', userPendingRequests());


    function AbortRequest(GroupRequestsService, $uibModalInstance, toaster, request) {
        var self = this;

        self.request = request;
        self.enabled = true;

        function handleSuccess(res) {
            $uibModalInstance.close(res);
        }

        function handleError(err) {
            var msg;

            if (err.data && err.data.error) {
                msg = err.data.error;
            } else {
                msg = err.statusText;
            }

            toaster.pop({
                type: 'error',
                body: msg
            });

            $uibModalInstance.dismiss(msg);
        }

        self.abortRequest = function () {
            GroupRequestsService.abortRequest(self.request).then(handleSuccess, handleError);
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };
    }

    function PendingRequestsController(Utils, GroupsService, GroupRequestsService, toaster, $uibModal) {
        var self = this;

        self.groupRequests = [];

        self.$onInit = $onInit;
        self.abortRequest = abortRequest;

        function $onInit() {
            self.voAdmin = Utils.isAdmin();
            loadGroupRequests();
            loadGroupCount();
        }

        function loadGroupCount() {
            return GroupsService.getGroupsCount().then(function (res) {
                self.groupsCount = res.data.totalResults;
            });
        }

        function loadGroupRequests() {
            return GroupRequestsService.getAllPendingGroupRequestsForAuthenticatedUser().then(function (reqs) {
                self.groupRequests = reqs;
            });
        }

        function abortRequest(request) {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/group-requests/cancel-group-request.dialog.html',
                controller: AbortRequest,
                controllerAs: '$ctrl',
                resolve: {
                    request: request
                }
            });

            modalInstance.result.then(function (r) {
                loadGroupRequests();
                toaster.pop({
                    type: 'success',
                    body: 'Request aborted'
                });
            }).catch(function (r) {
                loadGroupRequests();
            });
        }
    }


    function userPendingRequests() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/user/group-requests/pending-requests.component.html",
            bindings: {
                user: "<"
            },
            controller: [
                'Utils', 'GroupsService', 'GroupRequestsService', 'toaster', '$uibModal',
                PendingRequestsController
            ],
            controllerAs: '$ctrl'
        };
    }

}());