angular.module('dashboardApp').value('getUserInfo', getUserInfo);

angular.module('dashboardApp').config(function($stateProvider, $urlRouterProvider) {

	$urlRouterProvider.otherwise('/home');
	$stateProvider.state('home', {
		url : '/home',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/home/home.html',
		        controller: 'HomeController',
		        controllerAs: 'home'
		      }
		    }
	}).state('user', {
		url : '/user/:id',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/user/user.html',
		        controller: 'UserController',
		        controllerAs: 'user'
		      }
		    }
	}).state('group', {
		url : '/group/:id',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/group/group.html',
		        controller: 'GroupController',
		        controllerAs: 'group'
		      }
		    }
	}).state('users', {
		url : '/users',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/users/users.html',
		        controller: 'UsersController',
		        controllerAs: 'uc'
		      }
		    }
	}).state('groups', {
		url : '/groups',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/groups/groups.html',
		        controller: 'GroupsController',
		        controllerAs: 'gc'
		      }
		    }
	}).state('unauthorized', {
		url : '/unauthorized',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/unauthorized.html',
		        controller: 'UnauthorizedController',
		        controllerAs: 'unauthCtrl'
		      }
		    }
	}).state('requests', {
		url : '/requests',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/requests/management.html',
		        controller: 'RequestManagementController',
		        controllerAs: 'ctrl'
		      }
		    }
	}).state('error', {
		url : '/error',
		params: {
			error: {
				statusText: "Unknonwn error",
				data: {
					status: "500",
					detail: ""
				}
			}
		},
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/error.html',
		        controller: 'ErrorController',
		        controllerAs: 'errorCtrl'
		      }
		    }
	});
});