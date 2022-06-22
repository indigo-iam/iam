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

    function RemoveGroupManagerController($scope, $uibModalInstance, AccountGroupManagerService, Utils, group, account) {
        var self = this;
        self.group = group;
        self.account = account;

        self.enabled = true;

        function handleSuccess(res) {
            return $uibModalInstance.close(self.account);
        }

        function handleError(error) {
            var data = error.data;
            if (data.error) {
                $scope.operationResult = Utils.buildErrorResult(data.error);
            } else {
                $scope.operationResult = Utils.buildErrorResult(data);
            }

            self.enabled = true;
        }

        self.removeGroupManager = function () {
            self.enabled = false;
            AccountGroupManagerService.
                removeManagedGroupFromAccount(self.account.id, self.group.id).then(
                    handleSuccess, handleError);
        };

        self.cancel = function () {
            $uibModalInstance.dismiss("cancel");
        };
    }

    function AddGroupManagerController($scope, $uibModalInstance, AccountGroupManagerService, UsersService, Utils, group) {
        var self = this;
        self.group = group;

        self.enabled = false;
        self.gm = null;

        function handleSuccess(res) {
            return $uibModalInstance.close(self.gm);
        }

        function handleError(error) {
            var data = error.data;
            self.gm = null;
            if (data.error) {
                $scope.operationResult = Utils.buildErrorResult(data.error);
            } else {
                $scope.operationResult = Utils.buildErrorResult(data);
            }

            self.enabled = true;
        }

        self.cancel = function () {
            $uibModalInstance.dismiss("cancel");
        };


        self.addGroupManager = function () {
            self.enabled = false;
            AccountGroupManagerService.addManagedGroupToAccount(self.gm.id, self.group.id).then(
                handleSuccess, handleError);
        };

        self.lookupUser = function (val) {
            return UsersService.getUsersFilteredBy(0, 100, val).then(function (res) {
                return res.data.Resources;
            }).catch(function (res) {
                console.log(res);
                return [];
            });
        };

        self.userSelected = function (user) {
            self.gm = user;
            self.enabled = true;
        };
    }

    function GroupManagersController($uibModal, AccountGroupManagerService, Utils, toaster) {

        var self = this;

        self.loaded = false;
        self.privileged = false;
        self.managers = [];

        self.$onInit = function () {
            console.log('GroupManagersController onInit');
            self.privileged = self.groupManager || self.voAdmin;
            loadGroupManagers();
        };

        function loadGroupManagers() {
            if (self.privileged) {
                AccountGroupManagerService.getGroupManagers(self.group.id).then(function (managers) {
                    self.managers = managers;
                    self.loaded = true;
                }).catch(function (res) {
                    toaster.pop({
                        type: 'error',
                        body: res.statusText
                    });
                });
            } else {
                self.loaded = true;
            }
        }
        self.removeGroupManager = function (account) {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/group/managers/remove-group-manager.dialog.html',
                controller: RemoveGroupManagerController,
                controllerAs: '$ctrl',
                resolve: {
                    group: function () { return self.group; },
                    account: function () {
                        return account;
                    }
                }
            });

            modalInstance.result.then(function (user) {
                self.loadGroup().then(function (group) {
                    loadGroupManagers();
                    toaster.pop({
                        type: 'success',
                        body: `User '${user.name.formatted}' is no more a Group manager for '${group.displayName}'.`
                    });
                });
            });
        };

        self.addGroupManager = function () {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/group/managers/add-group-manager.dialog.html',
                controller: AddGroupManagerController,
                controllerAs: '$ctrl',
                resolve: { group: function () { return self.group; } }
            });

            modalInstance.result.then(function (user) {
                self.loadGroup().then(function (group) {
                    loadGroupManagers();
                    toaster.pop({
                        type: 'success',
                        body: `User '${user.name.formatted}' is now a Group manager for '${group.displayName}'.`
                    });
                });
            });
        };
    }

    angular.module('dashboardApp').component('groupManagers', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/group/managers/group.managers.component.html',
        bindings: { group: '<', loadGroup: '&', voAdmin: '<', groupManager: '<' },
        controller: [
            '$uibModal', 'AccountGroupManagerService', 'Utils', 'toaster', GroupManagersController
        ]
    });

}());