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

    function MyClientsController(ClientRegistrationService, $uibModal, toaster) {
        var self = this;

        self.redeemClient = redeemClient;
        self.deleteClient = deleteClient;
        self.onChangePage = onChangePage;

        self.$onInit = function () {
            console.debug('MyClientsController.self', self);
            self.currentPage = 1;
            self.itemsPerPage = 10;
            self.totalResults = self.clients.totalResults;
        };

        function onChangePage() {
            var currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

            if (currentOffset > self.totalResults && self.currentPage > 1) {
                self.currentPage--;
                currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;
            }

            retrieveClients(currentOffset, self.itemsPerPage).then(res => {
                self.totalResults = res.totalResults;
            });
        }

        function redeemClient() {
            var modalInstance = $uibModal.open({
                component: 'redeemClient'
            });

            modalInstance.result.then(function (res) {
                ClientRegistrationService.redeemClient(res.clientId, res.rat).then(rs => {
                    toaster.pop({
                        type: 'success',
                        body: 'Client redeemed!'
                    });
                    self.onChangePage();
                }).catch(err => {
                    var msg = 'Error redeeming client';

                    if (err.data) {
                        msg += ': ' + err.data.error;
                    }
                    toaster.pop({
                        type: 'error',
                        body: msg
                    });
                });
            }, function (res) {
                if (res !== 'cancel') {
                    toaster.pop({
                        type: 'error',
                        body: 'Error deleting client'
                    });
                }
            });
        }

        function retrieveClients(startIndex, itemsPerPage) {
            return ClientRegistrationService.retrieveOwnedClients(startIndex, itemsPerPage).then(res => {
                self.clients = res;
                self.totalResults = res.totalResults;
                return res;
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: 'Error retrieving clients!'
                });
                console.error("Retrieve owned clients failed", err);
            });
        }

        function deleteClient(client) {
            var modalInstance = $uibModal.open({
                component: 'confirmclientremoval',
                resolve: {
                    client: function () {
                        return client;
                    },
                    dynReg: function () {
                        return true;
                    }
                }
            });

            modalInstance.result.then(function (res) {
                toaster.pop({
                    type: 'success',
                    body: 'Client deleted!'
                });
                onChangePage();
            }, function (res) {
                if (res !== 'cancel') {
                    toaster.pop({
                        type: 'error',
                        body: 'Error deleting client'
                    });
                }
            });
        }
    }

    angular
        .module('dashboardApp')
        .component('myClients', myClients());


    function myClients() {

        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/user/myclients/myclients.component.html",
            bindings: {
                clients: '<'
            },
            controller: ['ClientRegistrationService', '$uibModal', 'toaster', MyClientsController],
            controllerAs: '$ctrl'
        };
    }
}());