# homeproxy

Set of tools to build your private home hosted proxy with Let's Encrypt TLS certificates, all your local apps stays local no public reach.

## Tools 

There are 4 docker containers that you need to host:

* autocertdelegate
* tlsrouter
* envoysds
* envoy

For documentation please read the [./build.sh](https://github.com/kushtrimjunuzi/homeproxy/blob/master/build.sh) bash script.

This project was not possible without Brad Fitzpatrick's project [autocertdelegate](https://github.com/bradfitz/autocertdelegate) thanks.
