# Yocto layer & Recipe

## Introduction

This Yocto layer/recipe was written on to be "sumo" (Yocto 2.5, Poky 19.0 and
BitBake 1.38) compliant. Dependencies:

	- Yocto 2.5
	- Open Embedded for Yocto 2.5

## Configuration & Generation

This Yocto recipe was tested on a Debian 8 system. Please, assure that you
use a Yocto 2.5 compatible Linux version. Check that following packages are 
installed on your system:

	1. wget
	2. git-core
	3. unzip
	4. make
	5. gcc
	6. g++
	7. build-essential
	8. subversion
	9. sed
	10. autoconf
	11. automake
	12. texi2html
	13. texinfo
	14. coreutils
	15. diffstat
	16. python-pysqlite2
	17. docbook-utils
	18. libsdl1.2-dev
	19. libxml-parser-perl
	20. libgl1-mesa-dev
	21. libglu1-mesa-dev
	22. xsltproc
	23. desktop-file-utils
	24. chrpath
	25. groff
	26. libtool
	27. xterm
	28. gawk
	29. fop

Let us assume that SRCDIR environment variable contains the absolute path to where 
the Yocto distribution is going to be generated.

Move to SRCDIR and clone the following GIT repositories:

	1. Poky: ```git clone -b sumo git://git.yoctoproject.org/poky```
	2. Open Embedded: ```git clone -b sumo git://git.openembedded.org/meta-openembedded```
	3. Bayshore Networks layer: ```git clone git://github.com/BayshoreNetworks/gargoyle.git```

Create the _build_ directory and run the Poky configuration script:

	```mkdir build; source poky/oe-init-build-env build```

Copy following configuration files provided in this repository to _build/conf_ folder:

	1. local.conf
	2. bblayers.conf (edit it with proper folder locations)

Run the command _bitbake core-image-minimal_ to generate the Yocto distribution. Please 
be patient, it takes around hours to finish :sleeping:

## Testing

Once we have generated the distribution, we can test it with the QEMU software:

```runqemu qemux86-64``` (user root, empty password)

The Gargoyle Protection for Linux installed as the following folder structure:

	- /usr/bin: binaries
	- /var/gargoyle: databases
	- /etc/gargoyle: template configuration files

To run the Gargoyle Protection for Linux software set the following environment 
variables to proper values:

	- GARGOYLE_DB
	- GARGOYLE_CONFIG
	- GARGOYLE_INTERNAL_PORT_CONFIG
	- GARGOYLE_SSHD_BRUTE_FORCE_CONFIG

Run main daemon ```gargoyle_pscand```
