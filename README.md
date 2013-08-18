sudoers-report
====================================

## DESCRIPTION

sudoers-report is a simple Perl script that parses a given sudoers file
and returns all user aliases and specs relevant to a given hostname. This
is especially useful with large legacy sudoers files where it is difficult
to tell who has access to do what on a given server.


## SYSTEM REQUIREMENTS

- Perl 5.8+
- Unix like operating system (OS X, FreeBSD, RHEL, Ubuntu, etc)
- Never tested on Microsoft Windows


## INSTALLATION

For now you just clone the repository and cd into the resulting directory:

```bash
$ git clone https://github.com/jeremypruitt/sudoers-report.git
$ cd sudoers-report
```

If you're installing from source, you can use [Bundler][bundler] to pick up all the
gems:

```bash
$ bundle install
```

## RUNNING

To get help on the command line utility, you can run it like so:

```bash
$ bin/sudoers-report --help
```

This will parse s sudoers file for a given hostname and return all
relevant user aliases and specs:

```bash
$ bin/sudoers-report --filename <path_to_sudoers_file> \
                     --hostname <target_hostname>
```


## CONTRIBUTE

If you'd like to hack on sudoers-report, start by forking the repo on GitHub:

http://github.com/jeremypruitt/sudoers-report

The best way to get your changes merged back into core is as follows:

1. Clone down your fork
1. Create a thoughtfully named topic branch to contain your change
1. Hack away
1. Add tests and make sure everything still passes (see: RUN THE TESTS)
1. If you are adding new functionality, document it in the README
1. Do not change the version number, I will do that on my end
1. If necessary, rebase your commits into logical chunks, without errors
1. Push the branch up to GitHub
1. Send a pull request to the jeremypruitt/sudoers-report project.


## RUN THE TESTS

```bash
$ perl t/Sudoers.t
```

