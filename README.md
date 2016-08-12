# sshexec

`sshexec` is a simple library for routing ssh exec commands. It is
designed to be easily used with the normal `ssh` command and make
use of stdin/stdout to the command.


## authorized keys

An authorizer interface is provided to handle authorizing public keys.
An implementation using github is provided which uses the github
username and public ssh key to authorize the user. Additionally
organization team membership can be used to authorize requests.
The github authorizer requires passing in an access token which needs
organization read access.

## echo server example

`go get github.com/dmcgowan/sshexec/cmd/echo-server`

### Run server

`echo-server -l localhost:2200 -t github-key -o myorg -a myteam`

### Run ssh

```
$ echo "hello" | ssh -p 2200 dmcgowan@localhost echo
hello
```

