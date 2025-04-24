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

    function ClientSecretViewController($uibModal, $uibModalInstance, toaster, ClientsService, data) {
        var $ctrl = this;
        $ctrl.data = data;
        $ctrl.isNewClient = data.isNewClient;
        $ctrl.newClient = data.client;
        $ctrl.secret = $ctrl.newClient.client_secret;
        $ctrl.clientId = $ctrl.newClient.client_id;
        $ctrl.showSecret = false;
        $ctrl.confirmation = true;

        self.clipboardSuccess = clipboardSuccess;
        self.clipboardError = clipboardError;
      
        $ctrl.ok = function() {
            $uibModalInstance.close($ctrl.selected);
        };
      
        $ctrl.closeModal = function() {
            $uibModalInstance.dismiss('cancel');
        };

        $ctrl.toggleSecretVisibility = function() {
            $ctrl.showSecret = !$ctrl.showSecret;
        };

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
    };

    function ClientController(ClientsService, FindService, toaster, $uibModal, $location) {
        var self = this;

        self.resetVal = resetVal;
        self.saveClient = saveClient;
        self.loadClient = loadClient;
        self.deleteClient = deleteClient;
        self.cancel = cancel;
        self.getClientStatusMessage = getClientStatusMessage;

        self.$onInit = function () {
            if (self.newClient) {
                self.clientVal = angular.copy(self.newClient);
                self.client = self.clientVal;
            } else {
                self.clientVal = angular.copy(self.client);
            }
            console.debug('ClientController.self', self);
        };

        function resetVal() {
            self.clientVal = angular.copy(self.client);
            toaster.pop({
                type: 'success',
                body: 'Client has been reset to the last saved information'
            });
        }

        function loadClient() {
            ClientsService.retrieveClient(self.client.client_id).then(function (data) {
                console.debug("Loaded client", data);
                self.client = data;
                self.clientVal = angular.copy(self.client);
            }).catch(function (res) {
                console.debug("Error retrieving client!", res);
                toaster.pop({
                    type: 'error',
                    body: 'Error retrieving client!'
                });
            });
        }

        function saveClient() {

            function handleSuccess(res) {
                self.client = res;
                self.clientVal = angular.copy(self.client);

                toaster.pop({
                    type: 'success',
                    body: 'Client saved!'
                });
                return res;
            }

            function handleError(res) {
                console.debug("Error saving client!", res);
                var errorMsg = 'Error saving client!';

                if (res.data && res.data.error) {
                    errorMsg = "Error saving client: " + res.data.error;
                }

                toaster.pop({
                    type: 'error',
                    body: errorMsg
                });
            }

            if (self.newClient) {
                return ClientsService.createClient(self.clientVal).then(res => {
                    toaster.pop({
                        type: 'success',
                        body: 'Client saved!'
                    });

                    var modalSecret = $uibModal.open({
                        templateUrl: '/resources/iam/apps/dashboard-app/components/clients/client/newclientsecretshow/newclientsecretshow.component.html',
                        controller: ClientSecretViewController,
                        controllerAs: '$ctrl',
                        resolve: {
                            data: {
                                client: res,
                                title: "New client credential details",
                                message: "Save this client credential on safe before press Confirm button",
                                isNewClient: true,
                            }
                        }
                    });

                    modalSecret.result
                        .then(() => {$location.path('/clients');})
                        .catch(() => {
                            toaster.pop({
                                type: 'error',
                                body: errorMsg
                            });
                        });
                }).catch(handleError);
            } else {

                return ClientsService.saveClient(self.clientVal.client_id, self.clientVal).then(handleSuccess)
                    .catch(handleError);

            }
        }

        function cancel() {
            $location.path('/clients');
        }

        function deleteClient() {
            var modalInstance = $uibModal.open({
                component: 'confirmclientremoval',
                resolve: {
                    client: function () {
                        return self.clientVal;
                    }
                }
            });

            modalInstance.result.then(function (res) {
                toaster.pop({
                    type: 'success',
                    body: 'Client deleted!'
                });
                $location.path('/clients');
            }, function (res) {
                if (res !== 'cancel') {
                    toaster.pop({
                        type: 'error',
                        body: 'Error deleting client'
                    });
                }
            });
        }

        function getClientStatusMessage() {
            self.clientStatusMessage = "Suspended by a VO admin on " + getFormatedDate(self.clientVal.status_changed_on);
        }

        function getFormatedDate(dateToFormat){
            var dateISOString = new Date(dateToFormat).toISOString();
            var ymd = dateISOString.split('T')[0];
            //Remove milliseconds
            var time = dateISOString.split('T')[1].slice(0, -5);
            return ymd + " " + time;
        }
    }

    angular
        .module('dashboardApp')
        .component('client', client());


    function client() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/client.component.html",
            bindings: {
                client: '<',
                systemScopes: '<',
                newClient: '<',
                clientOwners: '<'
            },
            controller: ['ClientsService', 'FindService', 'toaster', '$uibModal', '$location', ClientController],
            controllerAs: '$ctrl'
        };
    }

}());