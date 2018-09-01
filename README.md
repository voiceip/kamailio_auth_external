Kamailio mod auth_jwt
===================

This project is the auth_jwt module for Kamailio. With this module you can authenticate UA using jwt tokens.

![#f03c15](https://placehold.it/15/f03c15/000000?text=+) This is a work in progress. Please note this is not yet dev ready.


Building
--------

Fetch kamailio code:

    git clone --depth 1 --no-single-branch git@github.com:kamailio/kamailio.git kamailio
    cd kamailio
    git checkout -b 5.1 origin/5.1

Add the module:

    git submodule add git@github.com:voiceip/kamailio_auth_jwt.git src/modules/auth_jwt
    git submodule update

Login Inside The Build Environment

    export DIST=xenial VERSION=dev
    docker pull kamailio/pkg-kamailio-docker:${VERSION}-${DIST}
    docker run -i -t -v $(pwd):/code:rw kamailio/pkg-kamailio-docker:${VERSION}-${DIST} /bin/bash

Compile the module:

    export CC=gcc; cd /code; 
    make include_modules="auth_jwt" cfg
    make all


Alternatively you can follow the kamailio instructions at https://github.com/kamailio/kamailio/tree/master/test/travis .

