#!/bin/bash

#proxy=' -x socks5://127.0.0.1:1080'
proxy=''

retry=3
filepath=`readlink -f $0`
filedir=`dirname $filepath`
basedir=`dirname $filedir`

# exit on any error...
set -e

# Delete old data
rm -rf $basedir/res/oval/*
rm -rf $basedir/res/cve/*
rm -rf $basedir/res/exp/*
rm -rf $basedir/res/clamav/*

#### Download OVAL files manually####
echo 'Parsing the OVAL database'
cd $basedir/res/oval

# Ubuntu
curl -L --retry $retry $proxy https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.bionic.cve.oval.xml > com.ubuntu.bionic.cve.oval.xml
curl -L --retry $retry $proxy https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.xenial.cve.oval.xml > com.ubuntu.xenial.cve.oval.xml
curl -L --retry $retry $proxy https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.trusty.cve.oval.xml > com.ubuntu.trusty.cve.oval.xml
# Debian
curl -L --retry $retry $proxy https://www.debian.org/security/oval/oval-definitions-jessie.xml > oval-definitions-jessie.xml
curl -L --retry $retry $proxy https://www.debian.org/security/oval/oval-definitions-stretch.xml > oval-definitions-stretch.xml
curl -L --retry $retry $proxy https://www.debian.org/security/oval/oval-definitions-buster.xml > oval-definitions-buster.xml

# Red Hat
curl -L --retry $retry $proxy https://www.redhat.com/security/data/oval/Red_Hat_Enterprise_Linux_5.xml > Red_Hat_Enterprise_Linux_5.xml
curl -L --retry $retry $proxy https://www.redhat.com/security/data/oval/Red_Hat_Enterprise_Linux_6.xml > Red_Hat_Enterprise_Linux_6.xml
curl -L --retry $retry $proxy https://www.redhat.com/security/data/oval/Red_Hat_Enterprise_Linux_7.xml > Red_Hat_Enterprise_Linux_7.xml

# SUSE Linux Enterprise Server ( Server in German, American VPS helps little
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.11-patch.xml > suse.linux.enterprise.server.11-patch.xml
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.12-patch.xml > suse.linux.enterprise.server.12-patch.xml

# OpenSUSE
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/opensuse.13.1-patch.xml > opensuse.13.1-patch.xml
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/opensuse.13.2-patch.xml > opensuse.13.2-patch.xml
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/opensuse.leap.42.1-patch.xml > opensuse.42.1-patch.xml
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/opensuse.leap.42.2-patch.xml > opensuse.42.2-patch.xml
curl -L --retry $retry $proxy http://ftp.suse.com/pub/projects/security/oval/opensuse.leap.42.3-patch.xml > opensuse.42.3-patch.xml


## For NVD CVE
cd $basedir/res/cve
#curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.gz | gzip -d > nvdcve-2.0-2008.xml
#curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.gz | gzip -d > nvdcve-2.0-2009.xml
#curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.gz | gzip -d > nvdcve-2.0-2010.xml
#curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.gz | gzip -d > nvdcve-2.0-2011.xml
#curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.gz | gzip -d > nvdcve-2.0-2012.xml
curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.gz | gzip -d > nvdcve-2.0-2013.xml
curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.gz | gzip -d > nvdcve-2.0-2014.xml
curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.gz | gzip -d > nvdcve-2.0-2015.xml
curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz | gzip -d > nvdcve-2.0-2016.xml
curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2017.xml.gz | gzip -d > nvdcve-2.0-2017.xml
curl -L --retry $retry $proxy https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2018.xml.gz | gzip -d > nvdcve-2.0-2018.xml

## For Exploit-DB CVE
cd $basedir/res/exp
curl -L --retry $retry $proxy http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html > source-EXPLOIT-DB.html
curl -L --retry $retry $proxy https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv > files_exploits.csv
