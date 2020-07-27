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

    function DeleteScopeController($rootScope, $uibModalInstance, scope, toaster, ScopesService) {
        var self = this;
    
        self.scope = scope;
        self.enabled = true;
        self.error = undefined;
        
        self.deleteScope = function (scope) {
            self.error = undefined;
            self.enabled = false;
            ScopesService.removeScope(scope).then(
                function(response) {
                    console.info("Scope deleted", scope.value);
                    $rootScope.scopeCount--;
                    $uibModalInstance.close(scope);
                    self.enabled = true;
                },
                function (error) {
                console.error('Error deleting scope', error);
                self.error = error;
                self.enabled = true;
                toaster.pop({ type: 'error', body: error.data.error_description});
                });
        }
        self.cancel = function () {
          $uibModalInstance.dismiss('Dismissed');
        };
      }

    function AddScopeController($rootScope, $scope, $uibModal, $uibModalInstance, toaster, ScopesService) {
        var self = this;
    
        self.$onInit = function () {
          self.enabled = true;
          self.reset();
        }
    
        self.reset = function () {
          self.scope = {
            value: '',
            description: '',
            icon: '',
            restricted: false,
            defaultScope: false,
            structured: false,
            structuredParamDescription: null,
            structuredValue: null
          };
          if ($scope.scopeCreationForm) {
            $scope.scopeCreationForm.$setPristine();
          }
          self.enabled = true;
        }

        self.submit = function () {
    
          console.log("Scope info to add ", self.scope);
          self.enabled = false;

          var newScope = {}

          newScope.value = self.scope.value;
          newScope.description = self.scope.description;
          newScope.icon = self.scope.icon;
          newScope.restricted = self.scope.restricted;
          newScope.defaultScope = self.scope.defaultScope;
          newScope.structured = self.scope.structured;
          newScope.structuredParamDescription = null;
          newScope.structuredValue = null

          console.info("Adding scope ... ", newScope.value);

          ScopesService.addScope(newScope).then(
            function(response) {
                console.info("Scope Created", response.data);
                $uibModalInstance.close(response.data);
                self.enabled = true;
              },
            function (error) {
              console.error('Error creating scope', error);
              self.error = error;
              self.enabled = true;
              toaster.pop({ type: 'error', body: error.data.error_description});
            });
        }
    
        self.cancel = function () {
          $uibModalInstance.dismiss("cancel");
        }
      }

      function EditScopeController($rootScope, $scope, $uibModal, $uibModalInstance, scope, toaster, ScopesService) {
        var self = this;

        self.scope = scope
        self.$onInit = function () {
          self.enabled = true;
        }

        self.updateScope = function (scope) {
          
          self.scope = scope
    
          console.log("Scope info to add ", self.scope);
          self.enabled = false;

          var editedScope = {
            id: self.scope.id,
            value: self.scope.value,
            description: self.scope.description,
            icon: self.scope.icon,
            restricted: self.scope.restricted,
            defaultScope: self.scope.defaultScope,
            structured: self.scope.structured,
            structuredParamDescription: null,
            structuredValue: null
          }

          console.info("Updating scope ... ", editedScope.value, editedScope);

          ScopesService.updateScopeById(editedScope).then(
            function(response) {
                console.info("Scope Updated", editedScope.value);
                $rootScope.scopeCount++;
                $uibModalInstance.close(response.data);
                self.enabled = true;
              },
            function (error) {
              console.error('Error updating scope', error);
              self.error = error;
              self.enabled = true;
              toaster.pop({ type: 'error', body: error.data.error_description});
            });
        }
    
        self.cancel = function () {
          $uibModalInstance.dismiss("cancel");
        }
      }

    function ScopesListController($q, $scope, $rootScope, $uibModal, ModalService,
        ScopesService, toaster) {
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
              $rootScope.scopesCount = self.scopes.length;
              console.debug("init ScopesListController", self.scopes);
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

      self.handleDeleteSuccess = function (scope) {
        self.enabled = true;
        toaster.pop({
          type: 'success',
          body: 'Scope ' + scope.value + ' has been deleted successfully'
        });
        $rootScope.scopesCount--;
        self.loadAllScopes();
      };
  
      self.openDeleteScopeDialog = function (scope) {
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/scopes/scopeslist/scope.delete.dialog.html',
          controller: DeleteScopeController,
          controllerAs: '$ctrl',
          resolve: {
            scope: scope
          }
        });
  
        modalInstance.result.then(self.handleDeleteSuccess);
      };

      self.handleAddScopeSuccess = function (scope) {
        toaster.pop({
          type: 'success',
          body: 'Scope ' + scope.value + ' successfully added'
        });
        $rootScope.scopesCount++;
        self.loadAllScopes();
      };
  
      self.openAddScopeDialog = function () {
  
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/scopes/scopeslist/scope.add.dialog.html',
          controller: AddScopeController,
          controllerAs: '$ctrl'
        });
        console.debug(modalInstance);
        modalInstance.result.then(self.handleAddScopeSuccess);
      };

      self.handleEditScopeSuccess = function (scope) {
        toaster.pop({
          type: 'success',
          body: 'Scope ' + scope.value + ' successfully edited'
        });
        $rootScope.scopeCount++;
        self.loadAllScopes();
      };

      self.openEditScopeDialog = function (scope) {
  
        var modalInstance = $uibModal.open({
          templateUrl: '/resources/iam/apps/dashboard-app/components/scopes/scopeslist/scope.edit.dialog.html',
          controller: EditScopeController,
          controllerAs: '$ctrl',
          resolve: {
            scope: scope
          }
        });
        console.debug(modalInstance);
        modalInstance.result.then(self.handleEditScopeSuccess);
      };

    }

    angular
    .module('dashboardApp')
    .component(
      'scopeslist',
      {
        require: {
          $parent: '^scopes'
        },
        bindings: {
          scopes: '<',
          total: '<'
        },
        templateUrl: '/resources/iam/apps/dashboard-app/components/scopes/scopeslist/scopes.scopeslist.component.html',
        controller: ['$q', '$scope', '$rootScope', '$uibModal', 'ModalService',
          'ScopesService', 'toaster', ScopesListController]
      });
})();