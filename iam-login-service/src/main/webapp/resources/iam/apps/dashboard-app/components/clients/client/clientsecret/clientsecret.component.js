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

    function ClientSecretController(toaster, ClientsService) {
        var self = this;
        self.showSecret = false;

        self.toggleSecretVisibility = toggleSecretVisibility;
        self.clipboardSuccess = clipboardSuccess;
        self.clipboardError = clipboardError;
        self.rotateClientSecret = rotateClientSecret;
        self.isLimited = isLimited;
        self.rotateClientRat = rotateClientRat;

        function clipboardError(event) {
            toaster.pop({
                type: 'error',
                body: 'Could not copy secret to clipboard!'
            });
        }

        function isLimited() {
            return self.limited === 'true' | self.limited;
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

        function toggleSecretVisibility() {
            self.showSecret = !self.showSecret;
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

        function rotateClientSecret() {
            ClientsService.rotateClientSecret(self.client.client_id).then(res => {
                self.client = res;
                toaster.pop({
                    type: 'success',
                    body: 'Secret rotated for client ' + self.client.client_name
                });
            }).catch(res => {
                toaster.pop({
                    type: 'error',
                    body: 'Could not rotate secret for client ' + self.client.client_name
                });
            });
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
            controller: ['toaster', 'ClientsService', ClientSecretController],
            controllerAs: '$ctrl'
        };
    }

}());