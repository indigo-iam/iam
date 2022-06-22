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
(function() {
  'use strict';

  function TokensManagementController($scope, $rootScope, $uibModal, $q, toaster, TokensService, ClientsService, scimFactory) {

    var self = this;
    var USERS_CHUNCK_SIZE = 100;

    self.$onInit = function() {
      self.selected = 0;
      self.loadData();
    };

    self.loadFirstPageOfAccessTokens = function() {
        return TokensService.getAccessTokens(1,10).then(function(r) {
            self.accessTokensFirstResponse = r.data;
            $rootScope.accessTokensCount = r.data.totalResults;
            console.debug('accessTokensFirstResponse', self.accessTokensFirstResponse);
            return r.data;
        });
    }

    self.loadFirstPageOfRefreshTokens = function() {
        return TokensService.getRefreshTokens(1,10).then(function(r) {
            self.refreshTokensFirstResponse = r.data;
            $rootScope.refreshTokensCount = r.data.totalResults;
            console.debug('refreshTokensFirstResponse', self.refreshTokensFirstResponse);
            return r.data;
        });
    }

    self.loadUsers = function() {
        return scimFactory.getAllUsers(USERS_CHUNCK_SIZE)
            .then(function(data) {
                console.log('all users received');
                self.users = data;
            },
            function(error) {
                console.log('error while loading users', error);
                toaster.pop({ type: 'error', body: error });
            });
    }

    self.loadClients = function() {
        return ClientsService.getClientList().then(function(r) {
            var c = r.data;
            self.clients = c['Resources'];
            console.log('all clients received');
        });
    }

    self.isSelected = function(tabNumber) {
      return tabNumber == self.selected;
    }

    self.doSelect = function(tabNumber) {
      console.debug("doSelect", tabNumber);
      self.selected = tabNumber;
      if (tabNumber == 0) {
        self.selected = 0;
        $scope.$broadcast('refreshAccessTokensList');
      }
      if (tabNumber == 1) {
        self.selected = 1;
        $scope.$broadcast('refreshRefreshTokensList');
      }
    }

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

    self.loadData = function() {

        return self.openLoadingModal()
            .then(function() {
                var promises = [];
                promises.push(self.loadUsers());
                promises.push(self.loadClients());
                promises.push(self.loadFirstPageOfAccessTokens());
                promises.push(self.loadFirstPageOfRefreshTokens());
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
    .component('tokens', {
      templateUrl:
        '/resources/iam/apps/dashboard-app/components/tokens/tokens.component.html',
      controller: [
        '$scope', '$rootScope', '$uibModal', '$q', 'toaster', 'TokensService', 'ClientsService', 'scimFactory', TokensManagementController
      ]
    });
})();