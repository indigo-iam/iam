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



    function DeleteGroupController($rootScope, $uibModalInstance, toaster, scimFactory, group) {
        var self = this;

        self.group = group;
        self.enabled = true;
        self.error = undefined;

        self.doDelete = function (group) {
            self.error = undefined;
            self.enabled = false;
            scimFactory.deleteGroup(group.id).then(function (response) {
                $uibModalInstance.close(group);
                $rootScope.groupsCount--;
                self.enabled = true;
            }).catch(function (error) {
                console.error(error);
                self.enabled = true;
                self.cancel();
                toaster.pop({
                    type: 'error',
                    body: "" + error.data.detail
                });
            });
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };
    }

    function AddParentGroupController($rootScope, $uibModalInstance, toaster, scimFactory) {
        var self = this;

        self.group = {};

        self.$onInit = function () {
            self.enabled = true;
            self.resetGroup();
        };

        self.resetGroup = function () {
            self.group.displayName = "";
            self.group.schemas = [];
            self.group.schemas[0] = "urn:ietf:params:scim:schemas:core:2.0:Group";
            self.group.schemas[1] = "urn:indigo-dc:scim:schemas:IndigoGroup";
        };

        self.addGroup = function () {

            self.enabled = false;

            console.debug(self.group);

            scimFactory.createGroup(self.group).then(function (response) {
                $rootScope.groupsCount++;
                $uibModalInstance.close(response.data);
                self.enabled = true;
            }, function (error) {
                console.error(error);
                self.enabled = true;
                self.cancel();
                toaster.pop({
                    type: 'error',
                    body: "" + error.data.detail
                });
            });
        };

        self.cancel = function () {
            $uibModalInstance.dismiss("cancel");
        };
    }

    function AddSubgroupController($rootScope, $scope, $uibModalInstance, scimFactory, Utils, parent) {
        var self = this;

        self.parent = parent;
        self.group = {};

        self.$onInit = function () {
            self.enabled = true;
            self.resetGroup();
        };

        self.resetGroup = function () {
            self.group.displayName = "";
            self.group.schemas = [];
            self.group.schemas[0] = "urn:ietf:params:scim:schemas:core:2.0:Group";
            self.group.schemas[1] = "urn:indigo-dc:scim:schemas:IndigoGroup";
            self.group["urn:indigo-dc:scim:schemas:IndigoGroup"] = {
                "parentGroup": {
                    display: self.parent.displayName,
                    value: self.parent.id,
                    $ref: self.parent.meta.location
                }
            };
            $scope.operationResult = undefined;
        };

        self.addGroup = function () {

            self.enabled = false;
            $scope.operationResult = undefined;

            console.debug(self.group);

            scimFactory.createGroup(self.group).then(function (response) {
                $rootScope.groupsCount++;
                $uibModalInstance.close(response.data);
                self.enabled = true;
            }, function (error) {
                console.error('Error creating group', error);
                $scope.operationResult = Utils.buildErrorOperationResult(error);
                self.enabled = true;
            });
        };

        self.cancel = function () {
            $uibModalInstance.dismiss("cancel");
        };
    }

    function GroupsListController($filter, $q, $scope, $rootScope, $uibModal, $uibModalStack, ModalService,
        GroupsService, Utils, clipboardService, toaster, GroupRequestsService) {

        var self = this;

        self.labelName = labelName;
        self.isVoAdmin = isVoAdmin;

        self.$onInit = function () {
            self.loadInProgress = false;
            self.currentPage = 1;
            self.currentOffset = 1;
            self.itemsPerPage = 10;
            self.totalResults = self.total;
            self.sortByValue = "name";
            self.sortDirection = "asc";
            self.voAdmin = false;
            self.loaded = false;
        };

        $scope.$on('refreshGroupsList', function (e) {
            console.debug("received refreshGroupsList event");
            self.searchGroups();
        });

        self.updateGroupsCount = function (responseValue) {
            if (self.filter) {
                if (responseValue > $rootScope.groupsCount) {
                    $rootScope.groupsCount = responseValue;
                }
            } else {
                $rootScope.groupsCount = responseValue;
            }
        };

        function isVoAdmin() {
            return Utils.isAdmin();
        }

        function labelName(label) {
            if (label.prefix) {
                return label.prefix + "/" + label.name;
            }

            return label.name;
        }

        self.resetFilter = function () {
            self.filter = undefined;
            self.searchGroups(1);
        };

        self.searchGroups = function () {

            $uibModalStack.dismissAll('closing');

            $rootScope.pageLoadingProgress = 0;

            self.groups = [];

            self.currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

            var handleResponse = function (response) {
                self.totalResults = response.data.totalResults;
                angular.forEach(response.data.Resources, function (group) {
                    self.groups.push(group);
                });
                $rootScope.pageLoadingProgress = 100;
                self.updateGroupsCount(response.data.totalResults);
                self.loaded = true;
                GroupRequestsService.getAllPendingGroupRequestsForAuthenticatedUser().then(function (res) {
                    self.groupRequests = res;
                    self.loadingModal.dismiss("Cancel");
                });
            };

            var handleError = function (error) {
                self.loadingModal.dismiss("Error");
                toaster.pop({ type: 'error', body: error });
            };

            self.loadingModal = $uibModal.open({
                animation: false,
                templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
            });

            self.loadingModal.opened.then(function () {
                self.getGroupsList(self.currentOffset, self.itemsPerPage, self.filter, self.sortByValue, self.sortDirection).then(handleResponse, handleError);
            });

            self.loadingModal.result.catch(res => {
                if (res !== 'Cancel') {
                    return $q.reject(res);
                }
            });
        };

        self.getGroupsList = function (startIndex, count, filter, sortByValue, sortDirection) {
            if (filter === undefined) {
                return GroupsService.getGroupsSortBy(startIndex, count, sortByValue, sortDirection);
            }
            return GroupsService.getGroupsFilteredAndSortBy(startIndex, count, filter, sortByValue, sortDirection);
        };

        self.sortBy = function (sortByValue, sortDirection) {
            self.sortByValue = sortByValue;
            self.sortDirection = sortDirection;
            self.searchGroups(self.currentPage);
        };

        self.handleAddParentGroupSuccess = function (group) {
            toaster.pop({
                type: 'success',
                body: 'New Parent Group Added'
            });
            self.totalResults++;
            self.searchGroups(self.currentPage);
        };

        self.openAddParentGroupDialog = function () {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/groups/groupslist/group.add.dialog.html',
                controller: AddParentGroupController,
                controllerAs: '$ctrl'
            });

            modalInstance.result.then(self.handleAddParentGroupSuccess);
        };

        self.handleAddSubgroupSuccess = function (group) {
            toaster.pop({
                type: 'success',
                body: 'New group ' + group.displayName + ' added as subgroup of ' + group["urn:indigo-dc:scim:schemas:IndigoGroup"].parentGroup.display
            });
            self.totalResults++;
            self.searchGroups(self.currentPage);
        };

        self.openAddSubgroupDialog = function (group) {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/groups/groupslist/subgroup.add.dialog.html',
                controller: AddSubgroupController,
                controllerAs: '$ctrl',
                resolve: {
                    parent: group
                }
            });

            modalInstance.result.then(self.handleAddSubgroupSuccess);
        };

        self.handleDeleteSuccess = function (group) {
            self.enabled = true;
            toaster.pop({
                type: 'success',
                body: 'Group ' + group.displayName + ' successfully deleted'
            });
            self.totalResults--;
            if (self.currentOffset > self.totalResults) {
                if (self.currentPage > 1) {
                    self.currentPage--;
                }
            }
            self.searchGroups();
        };

        self.openDeleteGroupDialog = function (group) {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/groups/groupslist/group.delete.dialog.html',
                controller: DeleteGroupController,
                controllerAs: '$ctrl',
                resolve: {
                    group: group
                }
            });

            modalInstance.result.then(self.handleDeleteSuccess);
        };
    }

    angular
        .module('dashboardApp')
        .component(
            'groupslist', {
            require: {
                $parent: '^groups'
            },
            bindings: {
                groups: '<',
                total: '<',
                groupRequests: '<'
            },
            templateUrl: '/resources/iam/apps/dashboard-app/components/groups/groupslist/groups.groupslist.component.html',
            controller: ['$filter', '$q', '$scope', '$rootScope', '$uibModal', '$uibModalStack', 'ModalService',
                'GroupsService', 'Utils', 'clipboardService', 'toaster', 'GroupRequestsService', GroupsListController
            ]
        });
})();