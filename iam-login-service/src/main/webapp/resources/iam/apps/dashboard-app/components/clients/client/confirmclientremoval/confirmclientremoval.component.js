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


    function ConfirmClientRemovalController(ClientsService, ClientRegistrationService) {
        var self = this;

        self.ok = ok;
        self.cancel = cancel;
        self.enabled = true;
        self.dynReg = false;

        self.$onInit = function () {
            console.debug('ConfirmClientRemovalController.self', self);
            self.client = self.resolve.client;
            self.dynReg = self.resolve.dynReg;
        };

        function ok() {
            self.enabled = false;

            if (!self.dynReg) {
                ClientsService.deleteClient(self.client.client_id).then(function (res) {
                    self.close({ $value: res });
                }).catch(function (res) {
                    self.dismiss({ $value: res });
                });
            } else {
                ClientRegistrationService.deleteClient(self.client.client_id).then(function (res) {
                    self.close({ $value: res });
                }).catch(function (res) {
                    self.dismiss({ $value: res });
                });
            }
        }

        function cancel() {
            self.dismiss({ $value: 'cancel' });
        }

    }

    angular
        .module('dashboardApp')
        .component('confirmclientremoval', confirmclientremoval());


    function confirmclientremoval() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/confirmclientremoval/confirmclientremoval.component.html",
            bindings: {
                resolve: '<',
                close: '&',
                dismiss: '&'
            },
            controller: ConfirmClientRemovalController,
            controllerAs: '$ctrl'
        };
    }
}());