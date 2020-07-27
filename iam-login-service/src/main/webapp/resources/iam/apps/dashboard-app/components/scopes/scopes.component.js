/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
(function() {
    'use strict';

    function ScopesController($scope, $rootScope, $uibModal, $q, toaster, ScopesService) {

        var self = this;

        self.scopes = [];

        self.$onInit = function() {
            self.loadData();
        };

        self.openLoadingModal = function() {
            $rootScope.pageLoadingProgress = 0;
            self.modal = $uibModal.open({
                animation: false,
                templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
            });
            return self.modal.opened;
        };

        self.closeLoadingModal = function() {
            $rootScope.pageLoadingProgress = 100;
            self.modal.dismiss('Cancel');
        };

        self.handleError = function(error) {
            console.error(error);
            toaster.pop({ type: 'error', body: error });
        };


        self.loadAllScopes = function() {
            return ScopesService.getAllScopes().then(function(r) {
                self.scopes = r.data;
                $rootScope.scopesCount = r.data.length;
                return r;
            }).catch(function(r) {
                $q.reject(r);
            });
        }

        self.loadData = function() {

            return self.openLoadingModal()
                .then(function() {
                    var promises = [];
                    promises.push(self.loadAllScopes());
                    return $q.all(promises);
                })
                .then(function(response) {
                    self.closeLoadingModal();
                    self.loaded = true;
                })
                .catch(self.handleError);
        };
    }

    angular
        .module('dashboardApp')
        .component('scopes', {
            templateUrl: '/resources/iam/apps/dashboard-app/components/scopes/scopes.component.html',
            controller: [
                '$scope', '$rootScope', '$uibModal', '$q', 'toaster', 'ScopesService', ScopesController
            ]
        });
})();