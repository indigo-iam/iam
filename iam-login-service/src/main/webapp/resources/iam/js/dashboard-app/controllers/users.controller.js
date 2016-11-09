'use strict';

angular.module('dashboardApp').controller('UsersController', UsersController);

UsersController.$inject = [ '$scope', '$rootScope', '$uibModal', '$state', '$filter',
		'filterFilter', 'scimFactory', 'ModalService' , 'Utils'];

function UsersController($scope, $rootScope, $uibModal, $state, $filter, filterFilter,
		scimFactory, ModalService, Utils) {

	var users = this;

	// all the users list
	users.list = [];
	// filtered users to show
	users.filtered = [];
	// text to find to filter users
	users.searchText = "";

	// pagination controls
	users.currentPage = 1;
	users.entryLimit = 10; // items per page

	// functions
	users.resetFilters = resetFilters;
	users.rebuildFilteredList = rebuildFilteredList;
	users.getAllUsers = getAllUsers;
	users.openAddUserDialog = openAddUserDialog;
	users.deleteUser = deleteUser;
	users.removeUserFromList = removeUserFromList;
	users.loadUserList = loadUserList;

	// Controller actions:
	users.resetFilters();
	users.loadUserList();

	function resetFilters() {
		// needs to be a function or it won't trigger a $watch
		users.searchText = "";
	}

	function rebuildFilteredList() {
		
		users.filtered = filterFilter(users.list, function(user) {

			if (!users.searchText) {
				return true;
			}

			var query = users.searchText.toLowerCase();

			if (user.displayName.toLowerCase().indexOf(query) != -1) {
				return true;
			}
			if (user.name.formatted.toLowerCase().indexOf(query) != -1) {
				return true;
			}
			if (user.userName.toLowerCase().indexOf(query) != -1) {
				return true;
			}
			if (user.emails[0].value.toLowerCase().indexOf(query) != -1) {
				return true;
			}
			if (user.id.toLowerCase().indexOf(query) != -1) {
				return true;
			}
			return false;
		});
		users.filtered = $filter('orderBy')(users.filtered,	"name.formatted", false);
	}

	$scope.$watch('users.searchText', function() {

		users.rebuildFilteredList();
	});

	function loadUserList() {

		$rootScope.pageLoadingProgress = 0;
		users.loadingModal = $uibModal
		.open({
			animation: false,
			templateUrl : '/resources/iam/template/dashboard/users/loading-modal.html'
		});

		users.loadingModal.opened.then(function() {
			getAllUsers(1, users.entryLimit);
		});
	}

	function getAllUsers(startIndex, count) {

		scimFactory
				.getUsers(startIndex, count)
				.then(
						function(response) {
							
							angular.forEach(response.data.Resources, function(
									user) {
								users.list.push(user);
							});
							
							users.rebuildFilteredList();
							
							if (response.data.totalResults > (response.data.startIndex - 1 + response.data.itemsPerPage)) {
							
								users.getAllUsers(startIndex + count, count);
								$rootScope.pageLoadingProgress = Math.floor((startIndex + count) * 100 / response.data.totalResults);
							
							} else {
							
								$rootScope.pageLoadingProgress = 100;
								users.loadingModal.dismiss("Cancel");
							
							}
						}, function(error) {
							
							users.loadingModal.dismiss("Error");
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						
						});
	}

	function openAddUserDialog() {

		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/users/newuser.html',
					controller : 'AddUserController',
					controllerAs : 'addUserCtrl'
				});
		modalInstance.result.then(function(createdUser) {
			console.info(createdUser);
			users.list.push(createdUser);
			users.rebuildFilteredList();
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}
	
	function removeUserFromList(user) {

		var i = users.list.indexOf(user);
		users.list.splice(i, 1);

		users.rebuildFilteredList();
	}
	
	function deleteUser(user) {
		
		var modalOptions = {
			closeButtonText: 'Cancel',
            actionButtonText: 'Delete User',
            headerText: 'Delete user «' + user.name.formatted + '»',
            bodyText: `Are you sure you want to delete user '${user.name.formatted}'?`	
		};
		
		ModalService.showModal({}, modalOptions).then(
				function (){
					scimFactory.deleteUser(user.id).then(
						function(response) {
							users.removeUserFromList(user);
							$rootScope.loggedUser.totUsers = $rootScope.loggedUser.totUsers -1;
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + user.displayName + " has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	};
}
