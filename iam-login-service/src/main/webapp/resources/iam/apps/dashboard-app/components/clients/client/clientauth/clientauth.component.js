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

    function ClientAuthController() {
        var self = this;

        self.isLimited = isLimited;
        self.updateJwk = updateJwk;

        self.$onInit = function () {
            console.debug('ClientAuthController.self', self);
            initJwkOpt();
        };

        function updateJwk() {
            if (self.jwkOpt == 'uri') {
                delete self.client.jwk
            } else {
                delete self.client.jwks_uri
            }
        }

        function isLimited() {
            return self.limited === 'true' | self.limited;
        }

        function initJwkOpt() {
            if (self.client.jwks_uri) {
                self.jwkOpt = 'uri';
            } else if (self.client.jwk) {
                self.jwkOpt = 'jwk';
            } else {
                self.jwkOpt = 'uri';
            }
        }
    }

    angular
        .module('dashboardApp')
        .component('clientauth', clientauth());

    function clientauth() {

        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/clientauth/clientauth.component.html",
            bindings: {
                client: '=',
                newClient: '<',
                limited: '@'
            },
            controller: ClientAuthController,
            controllerAs: '$ctrl'
        }
    }

}());