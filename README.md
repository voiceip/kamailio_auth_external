Kamailio mod auth_external
===================

This project is the auth_external module for Kamailio. With this module you can send info to statsd/graphite.

Install
--------

Fetch kamailio code:

    git clone --depth 1 --no-single-branch git@github.com:kamailio/kamailio.git kamailio
    cd kamailio
    git checkout -b 5.1 origin/5.1

Add the module:

    git submodule add git@github.com:voiceip/kamailio_auth_external.git src/modules/auth_external
    git submodule update

Login Inside The Build Environment

	export DIST=xenial VERSION=dev
	docker pull kamailio/pkg-kamailio-docker:${VERSION}-${DIST}
	docker run -i -t -v $(pwd):/code:rw kamailio/pkg-kamailio-docker:${VERSION}-${DIST} /bin/bash

Compile the module:

	export CC=gcc; cd /code; 
    make include_modules="auth_external" cfg
    make all


Alternatively you can follow the kamailio instructions at https://github.com/kamailio/kamailio/tree/master/test/travis .

Module parameters
------------------

You can find the module parameters in the [Doxygen docs](doc/auth_external.txt)
