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

    function JoinGroupRequest($uibModalInstance, $q, GroupRequestsService, toaster, $sanitize, user, groups) {

        var self = this;

        self.user = user;
        self.groups = groups;
        self.enabled = true;
        self.selectedGroups = [];

        self.canSubmit = canSubmit;
        self.cancel = cancel;
        self.submit = submit;

        self.req = {
            notes: ""
        };

        function canSubmit() {
            return self.req.notes && self.selectedGroups.length > 0 && self.enabled;
        }

        function handleSuccess(res) {
            $uibModalInstance.close(res);
        }

        function handleError(err) {
            var msg;

            if (err.data) {
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

        function cancel() {
            $uibModalInstance.dismiss('Dismissed');
        }

        function submit() {
            var sanitizedNotes = $sanitize(self.req.notes);
            var promises = [];

            self.enabled = false;

            self.selectedGroups.forEach(function (g) {
                var req = {
                    notes: sanitizedNotes,
                    username: self.user.userName,
                    groupName: g.displayName
                };
                promises.push(GroupRequestsService.submit(req).catch(handleError));
            });

            return $q.all(promises).then(handleSuccess);
        }


        self.labelName = function (label) {
            if (label.prefix) {
                return label.prefix + "/" + label.name;
            }

            return label.name;
        };

    }

    function UserGroupRequestsController(GroupsService, GroupRequestsService, Utils, toaster, $uibModal) {
        var self = this;

        self.joinGroup = joinGroup;

        self.$onInit = function () {
            self.voAdmin = Utils.isAdmin();
        };

        function loadGroupRequests() {
            return GroupRequestsService.getAllPendingGroupRequestsForAuthenticatedUser().then(function (reqs) {
                self.groupRequests = reqs;
            });
        }

        function applicableGroup(g) {

            var matchingGroupRequests = self.groupRequests.filter(function (el) {
                return el.groupUuid == g.id;
            });

            var userGroups = [];

            if (self.user.groups) {
                userGroups = self.user.groups.filter(function (el) {
                    return el.value == g.id;
                });
            }

            return matchingGroupRequests.length === 0 && userGroups.length === 0;
        }

        function joinGroup() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/group-requests/join-group.dialog.html',
                controller: JoinGroupRequest,
                controllerAs: '$ctrl',
                size: 'lg',
                resolve: {
                    user: function () {
                        return self.user;
                    },
                    groups: function () {
                        return GroupsService.getAllGroups().then(function (res) {
                            return res.filter(applicableGroup);
                        });
                    }
                }
            });

            modalInstance.result.then(function (r) {
                loadGroupRequests();
                toaster.pop({
                    type: 'success',
                    body: `${r.length} request(s) submitted.`
                });
            });
        }
    }

    angular
        .module('dashboardApp')
        .component('joinGroup', {
            bindings: { user: '<', groupRequests: '=' },
            templateUrl: '/resources/iam/apps/dashboard-app/components/user/group-requests/join-group.component.html',
            controller: ['GroupsService', 'GroupRequestsService', 'Utils', 'toaster', '$uibModal', UserGroupRequestsController],
            controllerAs: '$ctrl'
        });
}());