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

    function GrantTypeController(OpenIDConfigurationService, $scope) {
        var self = this;

        self.toggleGrantType = toggleGrantType;
        self.clientHasGrantType = clientHasGrantType;
        self.isLimitedGrantType = isLimitedGrantType;

        self.limited = true;

        const LIMITED_GRANT_TYPES = ["password", "urn:ietf:params:oauth:grant-type:token-exchange"];

        self.$onInit = function () {
            console.debug('GrantTypeController.self', self);
            OpenIDConfigurationService.getConfiguration().then(function (res) {
                self.grantTypes = res.grant_types_supported;
                self.grantTypeMap = {};
                updateGrantTypeMap();
                $scope.$watch('$ctrl.client.grant_types', function (newVal, oldVal) {
                    updateGrantTypeMap();
                }, true);
            });
        };

        function updateGrantTypeMap() {
            self.grantTypes.forEach(gt => {
                self.grantTypeMap[gt] = clientHasGrantType(gt);
            });
        }

        function isLimitedGrantType(gt) {
            if (self.limited === 'false' || !self.limited) {
                return false;
            }

            return LIMITED_GRANT_TYPES.indexOf(gt) >= 0;
        }

        function toggleGrantType(gt) {
            var index = self.client.grant_types.indexOf(gt);

            if (index >= 0) {
                self.client.grant_types.splice(index, 1);
            } else {
                self.client.grant_types.push(gt);
            }

            self.grantTypes.forEach(ogt => {
                self.grantTypeMap[ogt] = clientHasGrantType(ogt);
            });
        }

        function clientHasGrantType(gt) {
            if (!self.client.grant_types) {
                return false;
            }
            return self.client.grant_types.indexOf(gt) != -1;
        }
    }


    angular
        .module('dashboardApp')
        .component('granttypelist', granttypelist());

    function granttypelist() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/granttypelist/granttypelist.component.html",
            bindings: {
                client: '=',
                limited: '@'
            },
            controller: ['OpenIDConfigurationService', '$scope', GrantTypeController],
            controllerAs: '$ctrl'
        };
    }

}());