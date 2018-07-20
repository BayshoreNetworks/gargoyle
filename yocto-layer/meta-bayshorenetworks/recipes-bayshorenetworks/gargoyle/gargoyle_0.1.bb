DESCRIPTION = "Gargoyle port scanning detection"
SECTION = "gargoyle"
DEPENDS = "sqlite3 libnetfilter-log"
LICENSE = "BSD"
LIC_FILES_CHKSUM = "file://LICENSE;md5=56d67c52d56e853efa5ac4590c19d2b6"

SRCREV = "5c7eb5ff81ab6e90e52a93585c83d1637f483a1c"
SRC_URI = "file://gargoyle_config.conf \
	   file://gargoyle_internal_port_config.conf \
	   file://gargoyle_ssh_bruteforce_config.conf \
	   git://github.com/BayshoreNetworks/gargoyle.git "

RRECOMMENDS_${PN} += " kernel-modules"

S = "${WORKDIR}/git"

inherit autotools-brokensep

# The autotools configuration I am basing this on seems to have a problem with a race condition
# when parallel make is enabled
PARALLEL_MAKE = ""

do_install_append() {
  install -d ${D}/${sysconfdir}/gargoyle 
  install -d ${D}/${localstatedir}/gargoyle 

  install -m 0755 ${S}/../gargoyle_config.conf ${D}/${sysconfdir}/gargoyle
  install -m 0755 ${S}/../gargoyle_internal_port_config.conf ${D}/${sysconfdir}/gargoyle
  install -m 0755 ${S}/../gargoyle_ssh_bruteforce_config.conf ${D}/${sysconfdir}/gargoyle
  install -m 0755 ${S}/db/gargoyle_attack_detect.db ${D}/${localstatedir}/gargoyle
  install -m 0755 ${S}/db/port_scan_detect.db ${D}/${localstatedir}/gargoyle
}
