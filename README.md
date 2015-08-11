Simple jwt token wrapper for Golang apps
=====================

This is a small wrapper around this https://github.com/dgrijalva/jwt-go package. This allows for any app to easily authenticate with a jwt token.
Use this to help minimize the code in your apps that use jwt tokens.

### Getting Started
You'll need to have a few things installed in order to work with this package.
- [Golang](https://golang.org/doc/install)

Get started by cloning down the repo that you will need:
```shell
git clone git@github.com:tetheredge/token-go.git
```

Your directory structure should end up looking something like this:
```
token/
├── README.md
├── token.go 
└── token_test.go 
```

Update your ~/.gitconfig file to allow go get to work with ssh
```shell
[url "git@github.com:"]
        insteadOf = https://github.com/
```

If you are cloning this for the first time, or need to get an update then run
```shell
# From within token/
go get
# or
go get -u
# You also need to setup the environment variable JWT_SECRET to the value
# of you secret key.  This variable is used to sign the token.
```

### How to use this package
```shell
# Add this code or something similar to your application
package main

import (
        "fmt"
        "github.com/tetheredge/token"
)

func main() {
        j := jwtToken.New()
        fmt.Println(j)

        j.Claims = map[string]interface{}{
                "test": "testing",
        }

        str, err := j.CreateToken(j.Claims)

        if err != nil {
                fmt.Println("Error: %v", err)
        }

        fmt.Println(str)

        token, err := j.ParseToken(str)

        if err != nil {
                fmt.Println("Error: %v", err)
        }

        fmt.Println(token)
}
```

### Standard Development

If you want to do testing of the application or any development, you'll need to run the following,
```shell
# From within token/
go test
```

To run a particular test you can run the following,
```shell
# From within token/
go test -run 'TestCreateToken'
```

Before pushing any changes that you want to commit, please run the following
commands,
```shell
# From within token/
go fmt 
go vet 
go test
```

Deployment
==========

This app does not deploy to any server, this is just a package that you
can include in your app.
