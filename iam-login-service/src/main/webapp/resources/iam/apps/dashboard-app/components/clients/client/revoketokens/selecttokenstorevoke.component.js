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


    function ClientTokenController(ClientsService) {
        var self = this;

        self.ok = ok;
        self.cancel = cancel;
        self.change = change;
        self.timeFormatter = timeFormatter;
        self.enabled = true;

        self.$onInit = function () {
            console.debug('ClientTokenController', self);
            self.client = self.resolve.client;

            self.revokeRefreshTokens = false;
            self.revokeAccessTokens = false;
            self.selectedDate = "";
        };

        function timeFormatter(timeObj) {
            let date = String(timeObj.getFullYear()) + "-" + String(timeObj.getMonth() + 1).padStart(2, "0") + "-" + String(timeObj.getDate()).padStart(2, "0");
            let time = "T" + String(timeObj.getHours()).padStart(2, "0") + ":" + String(timeObj.getMinutes()).padStart(2, "0") + ":" + String(timeObj.getSeconds()).padStart(2, "0");
            return date + time
        }

        function change() {
            let currentTime = document.getElementById("optionalTime");
            currentTime.setAttribute("max", timeFormatter(new Date()));
            currentTime.setAttribute("value", timeFormatter(new Date()))
            document.getElementById("selectDate").classList.toggle("hidden");
        }

        function ok() {
            if (self.selectedDate != "" && self.revokeAccessTokens) {
                self.selectedDate = timeFormatter(new Date(self.selectedDate));
            }
            console.log(self.selectedDate);
            if (!self.revokeAccessTokens && !self.revokeRefreshTokens) {
                self.dismiss({ $value: 'no-option' });
            }
            if (self.revokeRefreshTokens) {
                ClientsService.revokeRefreshTokens(self.client.client_id, self.selectedDate).then(function (res) {
                    self.close({ $value: res });
                }).catch(function (res) {
                    self.dismiss({ $value: res });
                });
            }
            if (self.revokeAccessTokens) {
                ClientsService.revokeAccessTokens(self.client.client_id, self.selectedDate).then(function (res) {
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
        .component('selecttokenstorevoke', confirmtokenremoval());


    function confirmtokenremoval() {
        return {
            templateUrl: '/resources/iam/apps/dashboard-app/components/clients/client/revoketokens/selecttokenstorevoke.component.html',
            bindings: {
                resolve: '<',
                close: '&',
                dismiss: '&'
            },
            controller: ['ClientsService', ClientTokenController],
            controllerAs: '$ctrl'
        };
    }
}());