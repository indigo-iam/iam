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

    function ModalClientSecretController($rootScope, $scope, $uibModal, $uibModalInstance, ClientsService, toaster, client) {
        var self = this;
        self.showSecret = false;

        // self.toggleSecretVisibility = toggleSecretVisibility;
        self.clipboardSuccess = clipboardSuccess;
        self.clipboardError = clipboardError;
        self.confirmation = true;
        self.clientId = client.client_id;
        self.clientName = client.client_name;
        self.isNewClient = !!self.clientId;
        self.parent = parent;
        self.showSecret = false;

        self.closeModal = function () {
            self.isModalOpen = false;
            $uibModalInstance.dismiss('Dismissed');
        };

        self.closeModal = function () {
            self.isModalOpen = false;
            $uibModalInstance.close();
        };

        self.toggleSecretVisibility = function() {
            self.showSecret = !self.showSecret;
        };

        self.confirmRequestNewSecret = function () {
            self.confirmation = true;
            var results = ClientsService.rotateClientSecret(client.client_id).then(res => {
                self.newSecret = res.client_secret;
                toaster.pop({
                    type: 'success',
                    body: 'Registration access token rotated for client ' + self.clientName
                });
            }).catch(error => {
                console.error(error);
                toaster.pop({
                    type: 'error',
                    body: 'Could not rotate secret for client ' + self.clientName
                });
            });
        }

        function clipboardError(event) {
            toaster.pop({
                type: 'error',
                body: 'Could not copy secret to clipboard!'
            });
        }

        function clipboardSuccess(event, source) {
            toaster.pop({
                type: 'success',
                body: 'Secret copied to clipboard!'
            });
            event.clearSelection();
            if (source === 'secret') {
                toggleSecretVisibility();
            }
        }
        self.confirmRequestNewSecret();
    }

    function ClientSecretController($uibModal, toaster, ClientsService) {
        var self = this;

        self.isLimited = isLimited;
        self.rotateClientRat = rotateClientRat;
        self.openModalRequestClientSecret = function () {
            self.isModalOpen = true;

            var modalSecret = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/clients/client/clientsecret/clientsecret.dialog.html',
                controller: ModalClientSecretController,
                controllerAs: '$ctrl',
                resolve: {
                    client: () => { return self.client }
                }
            });

            modalSecret.result.then(self.handleSuccess);
        };

        function isLimited() {
            return self.limited === 'true' | self.limited;
        }

        function rotateClientRat() {
            if (!isLimited()) {
                ClientsService.rotateRegistrationAccessToken(self.client.client_id).then(res => {
                    self.client = res;
                    toaster.pop({
                        type: 'success',
                        body: 'Registration access token rotated for client ' + self.client.client_name
                    });
                }).catch(res => {
                    toaster.pop({
                        type: 'error',
                        body: 'Could not rotate registration access token for client ' + self.client.client_name
                    });
                });
            }
        }

        self.$onInit = function () {
            console.debug('ClientSecretController.self', self);
        };
    }

    angular
        .module('dashboardApp')
        .component('clientsecret', clientsecret());


    function clientsecret() {

        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/clientsecret/clientsecret.component.html",
            bindings: {
                client: "=",
                newClient: "<",
                limited: '@'
            },
            controller: ['$uibModal', 'toaster', 'ClientsService', ClientSecretController],
            controllerAs: '$ctrl'
        };
    }

}());