### OVAL2DB, a tool to transfer OVAL data from XML to flat table in SQLite.

---

#### 1. Intro

[OVAL](https://oval.mitre.org/language/version5.10.1/OVAL_Language_Specification_01-20-2012.pdf) stands for 'Open Vulnerability and Assessment Language', it covers a lot of complicated things and belongs to a bigger project called [SCAP](https://csrc.nist.gov/projects/security-content-automation-protocol/).

It's been used by major Linux distributions to perform vulnerability assessment. Actually, they just use OVAL to organize their package updates information related to security problems. So we just extract the needed information from complex XML data structure into a simple table in SQLite. And this enables us to perform fast vul assessment over a large scale cluster.


#### 2. How to run
	
	bash run.sh

And then you may find the SQLite db file exists at res/db/vul_data.db

#### 3. Notice

* This is a side project based on what I did at Alibaba Cloud, when I was assigned to perform security assessment for VM images.

* For distributions like centos, which does not offer OVAL feeds, we use the data from RHEL instead. And of course, many pitfalls there.

* SUSE and OpenSUSE support exists already, but not added to this repo yet.

* Some tables in the database have not been created, I may finish it if got any interest or spare time.


#### 4. Refer

* https://oval.mitre.org/

* https://oval.mitre.org/language/version5.10.1/OVAL_Language_Specification_01-20-2012.pdf

* https://github.com/OpenSCAP/openscap/tree/maint-1.2/src/OVAL

* https://www.debian.org/security/oval/

* https://www.redhat.com/security/data/oval/

* https://people.canonical.com/~ubuntu-security/oval/G

* http://ftp.suse.com/pub/projects/security/oval

* https://nvd.nist.gov/vuln/data-feeds

* http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html

* https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv
