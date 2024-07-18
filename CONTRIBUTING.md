# INDIGO IAM developer guide

Thank you for investing your time in contributing to our project!

In this guide you will get an overview of the contribution workflow from opening an issue, creating a PR, reviewing, and merging the PR.

## Development environment

The INDIGO IAM service is a [Maven][maven] project built with Java 17.  
To download the necessary dependencies from the [CNAF Repository platform][repo] (e.g. to include the patched version of [MitreID][mitre]), add the maven [settings file][mvn-settings] locally, at `~/.m2/settings.xml`.

Run

```
$ mvn package
```

to build the project, or

```
$ mvn package -DskipTests
```
to skip tests execution.

You can use your favorite IDE for development.  
In case you are using Eclipse:

- install the `Spring Tools 4` plugin to use Spring buttons and configurations
- import the Java Google style
formatter (available [here][formatter]) to format your code.

Visual Studio Code has a similar extension that needs to be installed.

### Run the app

The main package is __iam-login-service__, listening by default on http://localhost:8080. To run it

- enable the `h2` and `dev` Spring profiles: these profiles allow to run the app in developer mode, where an in-memory database is enabled and populated with test users, clients, groups, etc. A web interface of the database is available at http://localhost:8080/h2-console. A test administrator can login into IAM with _admin/password_ credentials, while a test user with _test/password_. Connection to the database is possible by inserting the following parameters:
  - Driver Class: org.h2.Driver
  - JDBC URL: jdbc:h2:mem:iam
  - User Name: sa
  - Password: <empty>
- the main class to be run is `it.infn.mw.iam.IamLoginService`.

The __iam-test-client__ package is a simple web application used to showcase an authorization code flow where `iam-login-service` is the OAuth Authorization Server. It listens by default on http://localhost:9090/iam-test-client. The main class to be run is `it.infn.mw.tc.IamTestClientApplication`.

The __voms-aa__ package is a micro-service which provides backward-compatible VOMS support for a Virtual Organization managed by `iam-login-service`. It listens by default on http://localhost:15000. The main class to be run is `it.infn.mw.voms.VomsService`.


## Repository workflow

There are few rules that we want to follow during our development phase to make the history of this repository as clean as possible:

- the `master` branch is the one containing the latest official release
- the `develop` branch is a branch with a successful build, ready for next release
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

Even tough we will squash all commits of a PR into an inclusive, long commit, we invite you to follow few [best practices][git-commit]:

- fist letter of the commit must be capital
- tenses in the commit must not be past-like
- the first line of the commit must be included within 50 characters. Add a new blank line if you want to add more explanation of your commit (this will make more readable a `git log --oneline` command output, for instance).


## Useful references

### OAuth standard

- JSON Web Token ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519))
- Bearer Token Usage ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750))
- The OAuth 2.0 Authorization Framework ([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749))
- Device Code Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628))
- Token Exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693))
- Proof of Key Code Exchange ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636))

### Presentations

- [INDIGO IAM: current status & future developments](https://indico.stfc.ac.uk/event/763/sessions/510/attachments/1764/3125/INDIGO%20IAM%20Hackathon%202023.pdf)
- [INDIGO IAM: future developments and OIDC federations](https://agenda.infn.it/event/34683/contributions/197358/attachments/105521/148354/INDIGO-IAM_%20sviluppi_futuri_e_fed_OIDC.pdf)
- [Introduction to OAuth and its applications](https://agenda.infn.it/event/34111/attachments/100897/140421/Introduction-to-OAuth.pdf)
- [INDIGO IAM - status and evolution plans](https://indico.cern.ch/event/1185598/contributions/5043270/subcontributions/396287/attachments/2525106/4342827/October%202022%20Pre-GDB%20Authz%20and%20IAM%20workshop.pdf)
- [Status and prospects of WLCG transition to tokens](https://agenda.infn.it/event/30202/contributions/168567/attachments/91356/124066/Status%20and%20prospects%20of%20WLCG%20transition%20to%20tokens.pdf)



[maven]: https://maven.apache.org/
[repo]: https://repo.cloud.cnaf.infn.it/
[mitre]: https://github.com/indigo-iam/OpenID-Connect-Java-Spring-Server
[mvn-settings]: https://github.com/italiangrid/build-settings/blob/master/maven/cnaf-mirror-settings.xml
[formatter]: https://github.com/italiangrid/codestyle/blob/master/eclipse-google-java-codestyle-formatter.xml
[sonar]: https://docs.sonarcloud.io/
[git-commit]: https://cbea.ms/git-commit/