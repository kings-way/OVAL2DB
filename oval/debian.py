#!/usr/bin/env python
#encoding=utf8

import os
import sys
import pdb
path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/../')
sys.path.append(path)
from common_utils.database import DB_CVE, DB_OVAL
from common_utils.common_utils import read_xml
from common_utils.common_utils import get_element_text as text

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


class Debian:
    def __init__(self, major_release):
        self.base_url = 'oval-definitions-%s.xml'
        self.db_oval = DB_OVAL('debian', major_release)
        self.db_cve = DB_CVE()

        self.oval_generator = None
        self.oval_definitions = None
        self.oval_tests = None
        self.oval_objects = None
        self.oval_states = None

        self.package_name = ''
        self.fixed_version = ''
        self.major_release = major_release

        self.init()

    def init(self):

        if self.major_release == '10':
            release = 'buster'
        elif self.major_release  == '9':
            release = 'stretch'
        elif self.major_release == '8':
            release = 'jessie'
        elif self.major_release == '7':
            release = 'wheezy'
        else:
            raise RuntimeError("Version: Debian %s is not supported" % self.major_release)

        tree = read_xml(self.base_url % release)

        self.oval_generator = tree.getroot().getchildren()[0]
        self.oval_definitions = tree.getroot().getchildren()[1]
        self.oval_tests = tree.getroot().getchildren()[2]
        self.oval_objects = tree.getroot().getchildren()[3]
        self.oval_states = tree.getroot().getchildren()[4]
        del tree

        # # change the debian_version to be compatible with the OVAL states
        # self.sysinfo['config']['files']['/etc/debian_version'] = release

    def run(self):
        self.do_run()

    def do_run(self):
        count = 0
        for i in self.oval_definitions:

            oval_metadata = i.find('metadata')
            oval_criteria = i.find('criteria')
            oval_affected = oval_metadata.find('affected')
            try:
                title = oval_metadata.find('title')
                #product = oval_affected.find('product')
                date = oval_metadata.find('debian').find('date')
                description = oval_metadata.find('description')
                reference = oval_metadata.find('reference')
                if reference is None:
                    cve = None
                    ref = None
                else:
                    cve = reference.attrib['ref_id']
                    ref = reference.attrib['ref_url']

            except AttributeError, e:
                print
                print Fore.YELLOW + str(e) + " AttributeError! definition id: " + i.attrib['id']

            title = text(title)
            #product = text(product)
            description = text(description)
            date = text(date)

            result = self.check(oval_criteria)
            if result:
                #severity = self.get_severity(cve)
                severity = None
                count += 1
                if count % 1000 == 0:
                    self.db_oval.commit()
                    #print "Insert:", count
                self.db_oval.insert('debian', self.major_release, title, title, self.package_name, \
                                    self.fixed_version, severity, date, cve, description,ref)
            else:
                pass
        self.db_oval.commit()

    def check(self, element):
        #print "run_check: " + element.attrib['comment'] + "    " + str(element.tag == 'criterion')
        if element is None:
            return False
        elif element.tag == 'criterion':
            return self.do_check(element)
        elif element.tag == 'criteria':
            if element.attrib['operator'] == 'AND':
                result = True
                for i in element:
                    result = result and self.check(i)
                    if result is False:
                        break
                return result

            elif element.attrib['operator'] == 'OR':
                result = False
                for i in element:
                    result = result or self.check(i)
                    if result is True:
                        break
                return result
            else:
                raise RuntimeError("no operator within criteria: " + str(element.attrib))

    def do_check(self, criterion):
        result = False
        # First, get the element by id
        oval_test = self.oval_tests.find("*[@id='%s']" % criterion.attrib['test_ref'])

        oval_object= None
        oval_object_id = None
        oval_state = None
        oval_state_id = None

        # To get the child elements(object and state).
        if oval_test.find('object') is not None:
            oval_object_id = oval_test.find('object').attrib['object_ref']
        if oval_test.find('state') is not None:
            oval_state_id = oval_test.find('state').attrib['state_ref']

        # Then we get the oval_object and oval_state element
        # if the id is None, then the find method will return None too
        oval_object = self.oval_objects.find("*[@id='%s']" % oval_object_id)
        oval_state = self.oval_states.find("*[@id='%s']" % oval_state_id)

        # Finally, do the check work
        try:
            if oval_test.tag == 'uname_test':
                result = True

            # if the test is 'textfilecontent_test'
            elif oval_test.tag == 'textfilecontent_test' or oval_test.tag == 'textfilecontent54_test':
                result = True

            # if the test is 'dpkginfo_test'
            elif oval_test.tag == 'dpkginfo_test':
                pkg_name = oval_object.find('name').text
                if oval_state.tag == 'dpkginfo_state':
                    oval_state_evr = oval_state.find('evr')

                    if oval_state_evr is not None:
                        if oval_state_evr.attrib['operation'] == 'less than':
                            result = True
                            # result = self.is_less_than(ver1=pkg_ver, ver2=oval_state_evr.text, product=pkg_name)
                            self.package_name = pkg_name
                            self.fixed_version = oval_state_evr.text
                        else:
                            # result = False
                            raise RuntimeError("Unknown operation in state:" + oval_state.attrib['id'])
                    else:
                        # result = False
                        raise RuntimeError("element 'evr' not found in state:" + oval_state.attrib['id'])

                else:
                    # result = False
                    raise RuntimeError("Unknown tag of state: " + oval_state.attrib['id'])

        except KeyError, e:
            print(Fore.RED + "Error! Key %s not found in oval_test: %s" % (str(e), oval_test.attrib['id']))
            return False
        except AttributeError, e:
            print(Fore.RED + "Error! Attribute error %s in oval_test: %s " % (str(e), oval_test.attrib['id']))
            return False
        # print result
        return result


    def get_severity(self, cve):
        result = self.db_cve.get_by_id(cve)
        if len(result) == 0:
            return "low"
        else:
            result = result[0]
        score = result[3]
        poc = result[12]
        access_complexity = result[5]

        if score >9 or poc is not None:
            return "critical"
        elif score > 8 and access_complexity == 'LOW':
            return "important"
        elif score >= 5.5:
            return "moderate"
        else:
            return "low"


if __name__ == '__main__':
    deb = Debian('8')
    deb.run()

    deb = Debian('9')
    deb.run()

    deb = Debian('10')
    deb.run()
