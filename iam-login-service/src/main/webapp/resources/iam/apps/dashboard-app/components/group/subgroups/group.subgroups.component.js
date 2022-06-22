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

    function AddSubGroupController($scope, $rootScope, $uibModalInstance, Utils, scimFactory, group) {

        var self = this;

        self.parent = group;
        self.addSubGroup = addSubGroup;
        self.resetGroup = resetGroup;
        self.cancel = cancel;

        self.subgroup = {};

        function resetGroup() {
            self.subgroup.displayName = "";
            self.enabled = true;
        }

        self.resetGroup();

        function addSubGroup() {

            self.enabled = false;

            self.subgroup.schemas = ["urn:ietf:params:scim:schemas:core:2.0:Group", "urn:indigo-dc:scim:schemas:IndigoGroup"];
            self.subgroup["urn:indigo-dc:scim:schemas:IndigoGroup"] = {
                "parentGroup": {
                    display: self.parent.displayName,
                    value: self.parent.id,
                    $ref: self.parent.meta.location
                }
            };

            scimFactory.createGroup(self.subgroup).then(function (response) {
                $rootScope.loggedUser.totGroups = $rootScope.loggedUser.totGroups + 1;
                $uibModalInstance.close(response.data);
                self.enabled = true;
            }, function (error) {
                console.error('Error creating group', error);
                $scope.operationResult = Utils.buildErrorOperationResult(error);
                self.enabled = true;
            });
        }

        function cancel() {
            $uibModalInstance.dismiss("cancel");
        }
    }

    function SubgroupsController($rootScope, $filter, scimFactory, $uibModal, ModalService, toaster, GroupService) {

        var self = this;
        self.subgroups = [];
        self.openAddSubgroupDialog = openAddSubgroupDialog;
        self.deleteGroup = deleteGroup;

        self.loadSubgroups = loadSubgroups;

        self.$onInit = function () {
            self.currentPage = 1;
            self.itemsPerPage = 10;
            self.totalResults = 0;
            loadSubgroups(self.currentPage);
        };

        function handleSuccess(data) {
            self.subgroups = data.Resources;
            self.totalResults = data.totalResults;
            self.loadingModal.close();
        }

        function handleError(res) {
            console.error('Error loading subgroups: ', res);
            let error = res.statusText;

            if (res.data) {
                error = res.data.error;
            }

            toaster.pop({
                type: 'error',
                body: `${error}`
            });
        }

        function loadSubgroups() {
            self.currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

            self.loadingModal = $uibModal.open({
                animation: false,
                templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
            });

            self.loadingModal.opened.then(function () {
                GroupService.getSubgroups(self.group.id, self.currentOffset, self.itemsPerPage).then(handleSuccess, handleError);
            });

            self.loadingModal.result.catch(res => {
                return res;
            });
        }


        function openAddSubgroupDialog() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/group/subgroups/add-subgroup.dialog.html',
                controller: AddSubGroupController,
                controllerAs: '$ctrl',
                resolve: { group: function () { return self.group; } }
            });
            modalInstance.result.then(function (createdGroup) {
                self.loadGroup().then(function (g) {
                    self.group = g;
                    loadSubgroups(self.currentPage);
                    toaster.pop({
                        type: 'success',
                        body: `Group '${createdGroup.displayName}' CREATED successfully`
                    });
                });
            }, function () {
                console.info('Modal dismissed at: ', new Date());
            });
        }

        function deleteGroup(member) {

            var modalOptions = {
                closeButtonText: 'Cancel',
                actionButtonText: 'Delete Group',
                headerText: "Delete Group «" + member.display + "»",
                bodyText: `Are you sure you want to delete group '${member.display}'?`
            };

            ModalService.showModal({}, modalOptions).then(
                function () {
                    scimFactory.deleteGroup(member.value)
                        .then(function (response) {
                            self.loadGroup().then(function (res) {
                                self.group = res;
                                loadSubgroups(self.currentPage);
                                $rootScope.groupsCount = $rootScope.groupsCount - 1;
                                toaster.pop({
                                    type: 'success',
                                    body: `Group '${member.display}' DELETED successfully`
                                });
                            });
                        }, function (error) {
                            toaster.pop({
                                type: 'error',
                                body: `${error.data.detail}`
                            });
                        });
                });
        }
    }

    angular.module('dashboardApp').component('groupSubgroups', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/group/subgroups/group.subgroups.component.html',
        bindings: { group: '<', loadGroup: '&', voAdmin: '<', groupManager: '<' },
        controller: [
            '$rootScope', '$filter', 'scimFactory', '$uibModal', 'ModalService', 'toaster', 'GroupService', SubgroupsController
        ]
    });
})();