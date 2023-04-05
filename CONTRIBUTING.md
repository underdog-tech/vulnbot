# Contributing

First things first, thank you for contributing to this project! We welcome all
contributors and all form of contributions to Pinwheel's Open Source Software
projects. And keep in mind that contributions do come in many forms; reporting
bugs and participating in discussions about the project and its evolution is
often just as valuable as, if not moreso than, lines of code added.

## Table of Contents

* [Project Support](#project-support)
  * [Asking and Answering Questions](#asking-and-answering-questions)
  * [Reporting Bugs](#reporting-bugs)
  * [Feature Requests](#feature-requests)
* [Writing Code](#writing-code)
  * [Setting Up A Development Environment](#setting-up-a-development-environment)
  * [Code Style](#code-style)
* [Testing](#testing)


## Project Support

We do our best to keep all development, discussion, and planning of this project
open and public. And we ask that you do the same! Thankfully, GitHub provides a
number of tools to facilitate all of this, which we fully utilize.

### Asking and Answering Questions

If you have a question about how to use this project, how to contribute, how to
install, etc., we ask that you use the repository's [discussions] feature as
opposed to filing an issue. This allows us to keep the issue tracker focused on
work to be done on the project. The discussions section should also provide a
far more flexible and focused area for talking about these things that might not
necessarily result in direct code changes.

And if you see open discussions that you might know something about, please feel
free to speak up! We maintainers aren't always able to get to every question
immediately, so we absolutely welcome all voices in these discussions.

### Reporting Bugs

**Please do not report potential security vulnerabilities as issues! Instead,
we have enabled [private vulnerability reporting] which can be used to send a
private report directly to the maintainers of the project.**

Before filing a bug, please give a quick search through our [existing issues] to
see if it was already reported!

When reporting a new bug report, the following will help immensely in our
efforts to triage and fix it:

* Provide a clear description of what you expected to happen, and what actually
  happened instead.
  
  For example:
  > "When I ran X, I expected to see Y, but I saw Z instead"

  Instead of:
  > "X doesn't work right"

* Provide a list of steps to reproduce the bug. Try it again on your system to
  make sure it happens consistently.
* Tell us how often it happens. Does it happen every time? Every 5 times? Every
  second Tuesday at 11:34am? This is all very important information!
* Tell us a little bit about your system environment. What operation system are
  you running? What version of this tool? What version of Go?

Remember, the more information you provide, the easier it will be for us to
respond appropriately!

### Feature Requests

Similar to bug reports, the more information you can provide us with in your
request, the better.

* What problem are you attempting to solve?
* What functionality would you like to see added to help with this?
* How would you like to see it implemented?
* Are there any alternate ways of solving this problem that we might consider?

## Writing Code

### Setting Up A Development Environment

This project aims to keep development setup light. All that's necessary to get
started is an installation of Go! Go can be set up a number of ways:

* Download a binary release from the [official Go releases page]
* Install via [homebrew] (`brew install golang`)
* Use a version manager such as [asdf] (highly recommended)

As of the time of this writing, all development in this project is done against
**Go v1.20**.

### Code Style

If you've written Go before, you should be pretty familiar with our styling. All
of our code is formatted with `gofmt`! If you have not written Go before, or
would like a refresher, we highly encourage going through [Effective Go].

We ask that you also enable [EditorConfig] support in your editor, to help in
keeping things like spacing and line endings consistent.

### Committing Code

We generally follow [Conventional Commit] styling for our commit messages. While
this is not enforced at this time, it may be in the future to enable further
automation in our CI/CD process.

Additionally, due to the potentially sensitive nature of the data this project
is designed to work with, we require that ALL commits to this repository be
signed, preferably with a GPG key. This is essentially a way to prove that the
person committing the code is who they say they are, and prevents other people
from committing code on their behalf. More information can be found in GitHub's
excellent documentation: [Signing commits]

## Testing

While it may not always achieve this goal, we strive for this codebase to be
fully covered with effective tests. This doesn't mean writing tests just for the
sake of coverage. What it does mean is writing minimal, specific tests that
verify that the code does precisely what is intended. Tests should be written
with a focus on inputs and outputs, as opposed to the underlying implementation.
Test should also focus on the code written inside this project. They should NOT
be testing functionality of a third party library.

All of our tests can be run with the standard Go test runner:

```
> go test
```

The tests will be run in CI, and will be required to pass before new code can be
merged.


[asdf]: https://asdf-vm.com/
[Conventional Commit]: https://www.conventionalcommits.org/en/v1.0.0/
[discussions]: https://github.com/underdog-tech/dependabot-alert-bot/discussions
[EditorConfig]: https://editorconfig.org/
[Effective Go]: https://go.dev/doc/effective_go
[existing issues]: https://github.com/underdog-tech/dependabot-alert-bot/issues
[homebrew]: https://brew.sh/
[official Go releases page]: https://go.dev/dl/
[private vulnerability reporting]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability
[Signing commits]: https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits
