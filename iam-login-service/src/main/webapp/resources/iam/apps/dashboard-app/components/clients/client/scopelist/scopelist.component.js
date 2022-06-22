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

    function ScopeListController(StringSet, $scope, toaster) {
        var self = this;

        self.toggleSystemScope = toggleSystemScope;
        self.addCustomScope = addCustomScope;
        self.removeCustomScope = removeCustomScope;
        self.customScopes = customScopes;
        self.visibleSystemScopes = visibleSystemScopes;
        self.isRestrictedSystemScope = isRestrictedSystemScope;

        self.limited = true;
        self.scopeMap = {};

        self.$onInit = function () {
            updateScopeMap();
            $scope.$watch('$ctrl.client.scope', function (newVal, oldVal) {
                updateScopeMap();
            }, true);
            console.debug('ScopeListController.self', self);
        };

        function isLimited() {
            return (self.limited === 'true' || self.limited == true);
        }

        function isRestrictedSystemScope(scope) {
            return isLimited() && scope.restricted === true;
        }

        function isNotRestrictedSystemScope(scope) {
            return scope.restricted !== true;
        }

        function visibleSystemScopes() {
            if (!isLimited()) {
                return self.systemScopes;
            }

            var unrestrictedScopes = self.systemScopes.filter(isNotRestrictedSystemScope);

            var ownedScopes = self.systemScopes.filter(s => {
                return StringSet.containsItem(self.client.scope, s.value);
            });

            // this is what you get when u mess with us 
            var result = [... new Set([...unrestrictedScopes, ...ownedScopes])];
            console.debug('visible scopes: ', result);
            return result;
        }

        function updateScopeMap() {
            var scopeArray = scopesAsArray();

            self.systemScopes.forEach(ss => {
                self.scopeMap[ss.value] = scopeArray.indexOf(ss.value) >= 0;
            });

            self.ss = visibleSystemScopes();
        }

        function toggleSystemScope(scope) {

            if (StringSet.containsItem(self.client.scope, scope)) {
                self.client.scope = StringSet.removeItem(self.client.scope, scope);
            } else {
                self.client.scope = StringSet.addItem(self.client.scope, scope);
            }

            updateScopeMap();
        }

        function isCustomScope(scope) {
            return !self.systemScopes.some(s => {
                return s.value == scope;
            });
        }

        function customScopes() {
            return scopesAsArray().filter(isCustomScope);
        }

        function removeCustomScope(scope) {
            self.client.scope = StringSet.removeItem(self.client.scope, scope);
        }

        function addCustomScope() {

            var ss = self.systemScopes.find(ss => ss.value === self.customScopeValue);

            if (ss && isRestrictedSystemScope(ss)) {

                toaster.pop({
                    type: 'success',
                    body: `Bingo! You just discovered that '${self.customScopeValue}' is a restricted scope you're not allowed to request!`
                });

                self.customScopeValue = undefined;

            } else {
                self.client.scope = StringSet.addItem(self.client.scope, self.customScopeValue.trim());
                self.customScopeValue = undefined;
            }
        }

        function scopesAsArray() {
            if (!self.client.scope) {
                return [];
            }
            return self.client.scope.split(' ').filter(Boolean).sort();
        }

    }

    angular
        .module('dashboardApp')
        .component('scopelist', scopelist());

    function scopelist() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/scopelist/scopelist.component.html",
            bindings: {
                client: '=',
                systemScopes: '<',
                limited: '@'
            },
            controller: ['StringSet', '$scope', 'toaster', ScopeListController],
            controllerAs: '$ctrl'
        };
    }

}());