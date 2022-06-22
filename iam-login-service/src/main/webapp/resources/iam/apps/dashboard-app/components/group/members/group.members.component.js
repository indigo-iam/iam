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

    function GroupMembersController($rootScope, $filter, scimFactory, $uibModal, ModalService, toaster, GroupService) {

        var self = this;
        self.members = [];

        self.currentPage = 1;
        self.itemsPerPage = 10;
        self.totalResults = 0;

        self.deleteMember = deleteMember;

        self.loadMembers = loadMembers;

        self.loadMembers(self.currentPage);

        self.$onInit = function () {
            console.log('GroupMembersController onInit');
        };

        function handleSuccess(data) {
            self.members = data.Resources;
            self.totalResults = data.totalResults;
            self.loadingModal.close();
        }

        function handleError(res) {
            console.error('Error loading members: ', res);
            let error = res.statusText;

            if (res.data) {
                error = res.data.error;
            }

            toaster.pop({
                type: 'error',
                body: `${error}`
            });
        }

        function loadMembers() {
            self.currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

            self.loadingModal = $uibModal.open({
                animation: false,
                templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
            });

            self.loadingModal.opened.then(function () {
                GroupService.getGroupMembers(self.group.id, self.currentOffset, self.itemsPerPage).then(handleSuccess, handleError);
            });

            self.loadingModal.result.catch(res => {
                return res;
            });

        }


        function deleteMember(member) {

            var modalOptions = {
                closeButtonText: 'Cancel',
                actionButtonText: 'Remove membership',
                headerText: 'Remove «' + member.display + "» from «" + self.group.displayName + "»",
                bodyText: `Are you sure you want to remove '${member.display}' from '${self.group.displayName}'?`
            };

            ModalService.showModal({}, modalOptions).then(
                function () {
                    scimFactory.removeMemberFromGroup(self.group.id, member.value, member.$ref,
                        member.display)
                        .then(function (response) {
                            self.loadGroup().then(function (group) {
                                loadMembers(self.currentPage);
                                toaster.pop({
                                    type: 'success',
                                    body: `Member ${member.display} has been removed successfully`
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

    angular.module('dashboardApp').component('groupMembers', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/group/members/group.members.component.html',
        bindings: { group: '<', loadGroup: '&' },
        controller: [
            '$rootScope', '$filter', 'scimFactory', '$uibModal', 'ModalService', 'toaster', 'GroupService', GroupMembersController
        ]
    });
})();