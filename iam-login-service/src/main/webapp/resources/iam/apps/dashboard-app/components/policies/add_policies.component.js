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

    function PoliciesController($scope, $rootScope, $uibModal, $q, toaster, PoliciesService) {

        var self = this;

        self.policies = [];

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


        self.loadAllPolicies = function() {
            return PoliciesService.getAllPolicies().then(function(r) {
                self.policies = r.data;
                $rootScope.policiesCount = r.data.length;
                return r;
            }).catch(function(r) {
                $q.reject(r);
            });
        }

        self.loadData = function() {

            return self.openLoadingModal()
                .then(function() {
                    var promises = [];
                    promises.push(self.loadAllPolicies());
                    return $q.all(promises);
                })
                .then(function(response) {
                    self.closeLoadingModal();
                    self.loaded = true;
                })
                .catch(self.handleError);
        };
    }

/*    function AddPolicyController($rootScope, $scope, $uibModal, $uibModalInstance, toaster, scimFactory, PoliciesService) {
        var self = this;
		var USERS_CHUNCK_SIZE = 100;
    
        self.$onInit = function () {
          self.enabled = true;
          self.reset();
        }
    
        self.reset = function () {
          self.policy = {
            id: '',
            description: null,
            rule: '',
            matchingPolicy: '',
            account: null,
            group: null,
            scopes: [],
          };
          if ($scope.policyCreationForm) {
            $scope.policyCreationForm.$setPristine();
          }
          self.enabled = true;
        }

        self.submit = function () {
    
          console.log("Policy info to add ", self.policy);
          self.enabled = false;

          var newPolicy = {}

          newPolicy.id = self.policy.id;
          newPolicy.description = self.policy.description;
          newPolicy.rule = self.policy.rule;
          newPolicy.matchingPolicy = self.policy.matchingPolicy;
          newPolicy.account = self.policy.account;
          newPolicy.group = self.policy.group;
          newPolicy.scopes = self.policy.scopes.split(',');

          console.info("Adding policy ... ", newPolicy);

          PoliciesService.addPolicy(newPolicy).then(
            function(response) {
                console.info("Policy Created", response.data);
                $uibModalInstance.close(response.data);
                self.enabled = true;
              },
            function (error) {
              console.error('Error creating policy', error);
              self.error = error;
              self.enabled = true;
              toaster.pop({ type: 'error', body: error.data.error_description});
            });
        }
    
        self.cancel = function () {
          $uibModalInstance.dismiss("cancel");
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

      }

      function EditPolicyController($rootScope, $scope, $uibModal, $uibModalInstance, policy, toaster, PoliciesService) {
        var self = this;

        self.policy = policy
        self.$onInit = function () {
          self.enabled = true;
        }

        self.updatePolicy = function (policy) {
          
          self.policy = policy
    
          console.log("Policy info to add ", self.policy);
          self.enabled = false;

          var editedPolicy = {}
          
          editedPolicy.id = self.policy.id;
          editedPolicy.description = self.policy.description;
          editedPolicy.rule = self.policy.rule;
          editedPolicy.matchingPolicy = self.policy.matchingPolicy;
          editedPolicy.account = self.policy.account;
          editedPolicy.group = self.policy.group;
          editedPolicy.scopes = self.policy.scopes;

          console.info("Updating policy ... ", editedPolicy.id, editedPolicy);

          PoliciesService.updatePolicyById(editedPolicy).then(
            function(response) {
                console.info("Policy Updated", editedPolicy.id);
                $rootScope.policyCount++;
                $uibModalInstance.close(response.data);
                self.enabled = true;
              },
            function (error) {
              console.error('Error updating policy', error);
              self.error = error;
              self.enabled = true;
              toaster.pop({ type: 'error', body: error.data.error_description});
            });
        }
    
        self.cancel = function () {
          $uibModalInstance.dismiss("cancel");
        }
      }

      self.loadAllPolicies = function(page) {
          return PoliciesService.getAllPolicies().then(function(r) {
              self.policies = r.data;
              $rootScope.policiesCount = self.policies.length;
              console.debug("init PoliciesListController", self.policies);

			  //Pagination Control 
			  self.totalResults = self.policies.length,
			  self.filteredItems = [],   	
	  		  self.curPage = page,
	  		  self.itemsPerPage = 2
	  		  self.maxSize = 5

			  //this.items = self.policies;
 
			  self.numOfPages = function () {
			  return Math.ceil(self.policies.length / self.itemsPerPage);
 
			  };
 
			  $scope.$watch('curPage + numPerPage', function() {
			  var begin = ((self.curPage - 1) * self.itemsPerPage),
			  end = begin + self.itemsPerPage;
 
			  self.filteredItems = self.policies.slice(begin, end);
			  });
			  
			  return self.filteredItems
//
//              return r;
          }).catch(function(r) {
              $q.reject(r);
          })
      };

      self.loadData = function(page) {
		  
	  	  

          return self.openLoadingModal()
              .then(function() {
                  var promises = [];
                  promises.push(self.loadAllPolicies(page));
                  return $q.all(promises);
              })
              .then(function(response) {
                  self.closeLoadingModal();
                  self.loaded = true;
              })
              .catch(self.handleError);
      };

      self.handleAddPolicySuccess = function (policy) {
        toaster.pop({
          type: 'success',
          body: 'Policy ' + policy.id + ' successfully added'
        });
        $rootScope.policiesCount++;
		self.loadData(self.curPage);
      };*/

    angular
    .module('dashboardApp')
    .component(
      'add_policies',
      {
        templateUrl: '/resources/iam/apps/dashboard-app/components/policies/add_policies.component.html',
        controller: ['$q', '$scope', '$rootScope', '$uibModal', 'ModalService',
          'PoliciesService', 'toaster', "scimFactory", PoliciesController]
      });
})();