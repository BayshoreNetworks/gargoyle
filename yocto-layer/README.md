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

	1. build-dep
	2. qemu
	3. remove
	4. oss4-dev
	5. gawk
	6. wget
	7. git-core
	8. diffstat
	9. unzip
	10. texinfo
	11. gcc-multilib
	12. build-essential
	13. chrpath
	14. socat
	15. cpio
	16. python
	17. python3
	18. python3-pip
	19. python3-pexpect
	20. xz-utils
	21. debianutils
	22. iputils-ping

Let us assume that SRCDIR environment variable contains the absolute path to where 
the Yocto distribution is going to be generated.

Move to SRCDIR and clone the following GIT repositories:

	1. Poky: git clone -b sumo git://git.yoctoproject.org/poky
	2. Open Embedded: git clone -b sumo git://git.openembedded.org/meta-openembedded
	3. Bayshore Networks layer: git clone git://github.com/BayshoreNetworks/gargoyle.git

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

The Gargoyle Protection for Linux is installed as the following folder structure:

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
