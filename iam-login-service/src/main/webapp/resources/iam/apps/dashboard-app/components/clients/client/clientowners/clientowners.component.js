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

    function ClientOwnersController(ClientsService, $uibModal, toaster, Utils, $location) {
        var self = this;

        self.assignOwner = assignOwner;
        self.addOwnerByUsername = addOwnerByUsername;
        self.onUsernameKeydown = onUsernameKeydown;
        self.removeOwner = removeOwner;
        self.canRemove = canRemove;
        self.onChangePage = onChangePage;

        self.$onInit = function () {
            console.debug('ClientOwnersController.self', self);
            self.currentPage = 1;
            self.itemsPerPage = 10;
        };

        function onChangePage() {
            loadClientOwners();
        }

        function loadClientOwners() {
            var startIndex = (self.currentPage - 1) * self.itemsPerPage + 1;

            return ClientsService.retrieveClientOwners(self.client.client_id, startIndex, self.itemsPerPage).then(res => {
                if (self.currentPage > 1 && (!res.Resources || res.Resources.length === 0)) {
                    self.currentPage--;
                    return loadClientOwners();
                }
                self.clientOwners = res;
                self.listedBeforePage = false;
                if (!Utils.isAdmin() && !res.Resources.some(isMe)) {
                    return findMeBeforePage(1);
                }
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: "Error fetching client owners"
                });
            });
        }

        function isMe(owner) {
            return Utils.isMe(owner.id);
        }

        function findMeBeforePage(page) {
            if (page >= self.currentPage) {
                return;
            }
            var startIndex = (page - 1) * self.itemsPerPage + 1;

            return ClientsService.retrieveClientOwners(self.client.client_id, startIndex, self.itemsPerPage).then(res => {
                if (res.Resources.some(isMe)) {
                    self.listedBeforePage = true;
                    return;
                }
                return findMeBeforePage(page + 1);
            });
        }

        // Owners are listed by seniority: an owner can remove only the ones listed after them
        function canRemove(user, index) {
            if (Utils.isAdmin()) {
                return true;
            }
            if (isMe(user)) {
                return self.clientOwners.totalResults > 1;
            }
            var mine = self.clientOwners.Resources.findIndex(isMe);
            return mine < 0 ? !!self.listedBeforePage : index > mine;
        }

        function removeOwner(user) {
            ClientsService.removeClientOwner(self.client.client_id, user.id).then(res => {
                if (Utils.isMe(user.id) && !Utils.isAdmin()) {
                    toaster.pop({
                        type: 'success',
                        body: 'You are no longer an owner of this client'
                    });
                    $location.path('/home/clients');
                    return;
                }
                loadClientOwners();
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: (err.data && err.data.error) || "Error removing client owner"
                });
            });
        }

        // The field is inside the form of the client: Enter must not submit that form
        function onUsernameKeydown(event) {
            if (event.keyCode === 13) {
                event.preventDefault();
                if (self.newOwnerUsername) {
                    addOwnerByUsername();
                }
            }
        }

        function addOwnerByUsername() {
            ClientsService.assignClientOwnerByUsername(self.client.client_id, self.newOwnerUsername).then(res => {
                self.newOwnerUsername = '';
                loadClientOwners();
                toaster.pop({
                    type: 'success',
                    body: 'Owner added'
                });
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: (err.data && err.data.error) || "Error assigning client owner"
                });
            });
        }

        function assignOwner() {
            var modalInstance = $uibModal.open({
                component: 'findUserDialog',
                resolve: {
                    title: function () {
                        return 'Assign client owner';
                    },
                    action: function () {
                        return 'Assign owner';
                    }
                }
            });

            modalInstance.result.then(user => {
                console.log("Selected user: ", user);
                ClientsService.assignClientOwner(self.client.client_id, user.id).then(res => {
                    loadClientOwners();
                }).catch(err => {
                    toaster.pop({
                        type: 'error',
                        body: "Error assigning client owner"
                    });
                });
            });
        }
    }

    angular
        .module('dashboardApp')
        .component('clientOwners', component());


    function component() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/clientowners/clientowners.component.html",
            bindings: {
                client: '=',
                clientOwners: '='
            },
            controller: ['ClientsService', '$uibModal', 'toaster', 'Utils', '$location', ClientOwnersController],
            controllerAs: '$ctrl'
        };
    }

}());