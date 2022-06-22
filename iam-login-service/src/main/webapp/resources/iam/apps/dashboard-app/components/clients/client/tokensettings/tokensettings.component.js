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

    function TokenSettingsController(StringSet, $scope) {
        var self = this;

        var DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
        var REFRESH_TOKEN_GRANT_TYPE = 'refresh_token';
        var OFFLINE_ACCESS = 'offline_access';

        self.toggleOfflineAccess = toggleOfflineAccess;
        self.canIssueRefreshTokens = false;
        self.hasDeviceCodeGrantType = false;


        self.$onInit = function () {
            console.debug('TokenSettingsController.self', self);
            if (!self.client.access_token_validity_seconds) {
                self.client.access_token_validity_seconds = 0;
            }
            if (!self.client.refresh_token_validity_seconds) {
                self.client.refresh_token_validity_seconds = 0;
            }

            $scope.$watch('$ctrl.client.access_token_validity_seconds', function handleChange(newVal, oldVal) {
                if (!self.client.access_token_validity_seconds) {
                    self.client.access_token_validity_seconds = 0;
                }
            });

            $scope.$watch('$ctrl.client.refresh_token_validity_seconds', function handleChange(newVal, oldVal) {
                if (!self.client.refresh_token_validity_seconds) {
                    self.client.refresh_token_validity_seconds = 0;
                }
            });

            $scope.$watch('$ctrl.client.grant_types', function handleChange(newVal, oldVal) {
                updateCanIssueRts();
                self.hasDeviceCodeGrantType = self.client.grant_types.indexOf(DEVICE_CODE_GRANT_TYPE) >= 0;
            }, true);

            $scope.$watch('$ctrl.client.scope', function handleChange(newVal, oldVal) {
                updateCanIssueRts();
            }, true);

        };

        function updateCanIssueRts() {
            var gt = self.client.grant_types.indexOf(REFRESH_TOKEN_GRANT_TYPE) >= 0;
            var scope = StringSet.containsItem(self.client.scope, OFFLINE_ACCESS);
            self.canIssueRefreshTokens = gt && scope;
        }

        function toggleOfflineAccess() {
            self.client.scope = StringSet.addItem(self.client.scope, OFFLINE_ACCESS);
            if (self.client.grant_types.indexOf(REFRESH_TOKEN_GRANT_TYPE) < 0) {
                self.client.grant_types.push(REFRESH_TOKEN_GRANT_TYPE);
            }
            updateCanIssueRts();
        }
    }

    angular
        .module('dashboardApp')
        .component('tokensettings', tokensettings());

    function tokensettings() {

        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/tokensettings/tokensettings.component.html",
            bindings: {
                client: '='
            },
            controller: ['StringSet', '$scope', TokenSettingsController],
            controllerAs: '$ctrl'
        };
    }

}());