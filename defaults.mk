
ifndef DEPLOY_TO
	DEPLOY_TO=/opt/gargoyle_pscand/
endif

export SYSROOT?=/

export CCC=$(CROSS_COMPILE)g++
export CC=$(CROSS_COMPILE)gcc
export AR=$(CROSS_COMPILE)ar
export STRIP=$(CROSS_COMPILE)strip
export OBJCOPY=$(CROSS_COMPILE)objcopy

# For the target platform, we may need to build netfilter ourselves, so enable
# these overrides in that scenario, otherwise, on debian for instance, these will
# be left blank.
export NETFILTER_INCLUDE_PATH?=
export NETFILTER_LIBRARY_PATH?=

# We might have compiled libmnl separately in which case this line must be overriden
export NETFILTER_LIBS_EXTRA?=

$(info DEPLOY_TO	 = $(DEPLOY_TO))
$(info PATH	 		 = $(PATH))
