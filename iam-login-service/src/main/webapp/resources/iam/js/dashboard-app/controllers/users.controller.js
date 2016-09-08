'use strict';

angular.module('dashboardApp').controller('UsersController', UsersController);

UsersController.$inject = [ '$scope', '$location', '$state', '$filter',
		'filterFilter', 'scimFactory' ];

function UsersController($scope, $location, $state, $filter, filterFilter,
		scimFactory) {

	var uc = this;

	uc.users = [];

	// create empty search model (object) to trigger $watch on update
	uc.search = {};

	// pagination controls
	uc.currentPage = 1;
	uc.totalItems = uc.users.length;
	uc.entryLimit = 10; // items per page

	// functions
	uc.resetFilters = resetFilters;
	uc.updateNoOfPages = updateNoOfPages;
	uc.updateTotalItems = updateTotalItems;

	uc.getAllUsers = getAllUsers;

	// Controller actions:
	uc.resetFilters()
	uc.getAllUsers(1, uc.entryLimit); // eval uc.users

	function updateTotalItems() {

		uc.totalItems = uc.users.length;
	}

	function updateNoOfPages() {

		uc.noOfPages = Math.ceil(uc.totalItems / uc.entryLimit);
	}

	function resetFilters() {
		// needs to be a function or it won't trigger a $watch
		uc.search = {};
	}
	;

	// $watch search to update pagination
	$scope.$watch('uc.search', function(newVal, oldVal) {
		uc.filtered = filterFilter(uc.users, newVal);
		uc.updateTotalItems();
		uc.updateNoOfPages();
		uc.currentPage = 1;
	}, true);

	function getAllUsers(startIndex, count) {

		scimFactory
				.getUsers(startIndex, count)
				.then(
						function(response) {
							angular.forEach(response.data.Resources, function(
									user) {
								uc.users.push(user);
							});
							uc.users = $filter('orderBy')(uc.users,
									"name.formatted", false);
							uc.updateTotalItems();
							uc.updateNoOfPages();
							if (response.data.totalResults > (response.data.startIndex + response.data.itemsPerPage)) {
								uc.getAllUsers(startIndex + count, count);
							}
						}, function(error) {
							$state.go("error", {
								"error" : error
							});
						});
	}
}
