# INDIGO IAM developer guide

Thank you for investing your time in contributing to our project!

In this guide you will get an overview of the contribution workflow from opening an issue, creating a PR, reviewing, and merging the PR.

## Development environment

The INDIGO IAM service is a [Maven][maven] project build with Java 17.  
Run

```
$ mvn package
```

to build the project, or

```
$ mvn package -DskipTests
```
to skip tests execution.

You can use your favorite IDE for development (Eclipse is the one adopted at the time of writing).
Install the `Spring Tools 4` plugin to use Spring buttons and configurations. Please use a modified Google style
formatter available [here](utils/codestyle-formatter-CNAF.xml) to format your code.

### Run the app

The main package is __iam-login-service__, listening by default on http://localhost:8080. To run it

- enable `h2-test`, `dev` profiles: these profiles allow to run the app in developer mode, where an in memory database is enabled and populated with test users, clients, groups, etc. A web interface of the database is available at http://localhost:8080/h2-console
- the main class to be run is `it.infn.mw.iam.IamLoginService`.

The __iam-test-client__ package is a simple web application used to showcase an authorization code flow where `iam-login-service` is the OAuth Authorization Server. It listens by default on http://localhost:9090/iam-test-client. The main class to be run is `it.infn.mw.tc.IamTestClientApplication`.

The __voms-aa__ package is a micro-service which provides backward-compatible VOMS support for a Virtual Organization managed by `iam-login-service`. It listens by default on http://localhost:15000. The main class to be run is `it.infn.mw.voms.VomsService`.


## Repository workflow

There are few rules that we want to follow during our development phase to make the history of this repository as clean as possible:

- the `master` branch is the one containing the latest official release
- the `develop` branch is a buildable branch, ready for next release
- when you want to develop some feature, create a new branch starting from `develop`
  - if you spot a problem within IAM, search if an issue already exists. If not, create a new issue
  - create a new branch named `issue-<number>`
  - develop your own solution
  - when you are satisfied with your work, create a Pull Request from branch `issue-<number>` to `develop`
  - wait for the [GitHub workflow](.github/workflows/sonar.yaml) to finish running. If the build succeeds, a [Sonar analysis][sonar] for code quality runs. Please fix spotted problems, if any. We want to keep as much code coverage as possible (a lower threshold is set to 85%), so add JUnit tests to the uncovered parts of your code.


### Pull Request workflow

When you are finished with the changes, create a pull request, also known as a PR, and

- add someone of the team as reviewer
- link the PR to [related issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
- once you submit your PR, a team member will review your proposal
  - we may ask questions or request additional information
  - we may ask for changes to be made before a PR can be merged, either using [suggested changes](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request) or pull request comments
  - as you update your PR and apply changes, mark each conversation as [resolved](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/commenting-on-a-pull-request#resolving-conversations).


### Commits

Even tough we will squash all commits of a PR into an inclusive, long commit, we invite you to follow few best practices:

- fist letter of the commit must be capital
- tenses in the commit must not be past-like
- the first line of the commit must be included within 50 characters. Add a new blank line if you want to add more explanation of your commit (this will make more readable a `git log --oneline` command output, for instance).


## Useful references

### Code base technologies

### OAuth standard



[maven]: https://maven.apache.org/
[sonar]: https://docs.sonarcloud.io/