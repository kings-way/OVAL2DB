#!/usr/bin/env python
#encoding=utf8

import re
import os
import sys
import pdb
path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/../')
sys.path.append(path)
from common_utils.database import DB_OVAL
from common_utils.common_utils import read_xml
from common_utils.common_utils import get_element_text as text
try:
	import xml.etree.cElementTree as ET
except ImportError:
	import xml.etree.ElementTree as ET


class RedHat_Base:
	def __init__(self, major_release):
		self.db = DB_OVAL('redhat', major_release)
		self.major_release = major_release
		self.filename = 'Red_Hat_Enterprise_Linux_%s.xml'
		version_map = open(os.path.dirname(os.path.abspath(__file__)) + '/../res/filter/rpm_version_map.list').read()
		self.version_map = []
		self.version_map_set = set()
		for line in version_map.splitlines():
			line = line.strip()
			if line == '' or line.startswith('#'):
				continue
			else:
				# [['centos', '6', 'httpd', '2.2.15-60.el6.centos.6', '2.2.15-60.el6_9.6'], ...]
				line = line.split()
				self.version_map.append(line)
				self.version_map_set.add(line[2])

		self.oval_generator = None
		self.oval_definitions = None
		self.oval_tests = None
		self.oval_objects = None
		self.oval_states = None

		self.product = ''
		self.fixed_version = ''

		self.init()

	def init(self):
		tree = read_xml(self.filename % self.major_release)

		self.oval_generator = tree.getroot().getchildren()[0]
		self.oval_definitions = tree.getroot().getchildren()[1]
		self.oval_tests = tree.getroot().getchildren()[2]
		self.oval_objects = tree.getroot().getchildren()[3]
		self.oval_states = tree.getroot().getchildren()[4]
		del tree

	def run(self):
		self.do_run()

	def do_run(self):
		for i in self.oval_definitions:
			oval_metadata = i.find('metadata')
			oval_criteria = i.find('criteria')

			oval_advisory = oval_metadata.find('advisory')

			title = oval_metadata.find('title')
			severity = oval_advisory.find('severity')
			description = oval_metadata.find('description')
			references = oval_metadata.findall('reference')
			cves = oval_advisory.findall('cve')

			cve = []
			for _cve in cves:
				cve.append(text(_cve))

			ref = []
			for _ref in references:
				ref.append(_ref.attrib['ref_url'])

			date = oval_advisory.find('issued').attrib['date']
			title_detailed = text(title)
			title = title_detailed[:14]
			severity = text(severity).lower()
			description = text(description)
			result = self.check(oval_criteria)
			if result:
				# {'title':str, 'cve':str or list, 'date':str, 'product':str, 'ver_old':str, 'ver_new':str, 'desc':str, 'ref':str or list  }
				#self.db.insert({'distro':'redhat', 'release':self.major_release, 'title':title, 'package':result[0], 'fixed_version':result[1], 'severity':severity, 'date':date, 'cve':cves, 'desc':description, 'ref':references })
				self.db.insert('redhat', self.major_release, title, title_detailed, self.product, self.fixed_version, severity, date, '||'.join(cve), description, '||'.join(ref))
			else:
				pass
		self.db.commit()

	def check(self, element):
		if element is None:
			return False
		elif element.tag == 'criterion':
			#print "run_check: " + element.attrib['comment'] +  ":", self.do_check(element)
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
			# if the test is 'rpminfo_test'
			if oval_test.tag == 'rpminfo_test':
				pkg_name = oval_object.find('name').text

				if oval_state.tag == 'rpminfo_state':
					oval_state_evr = oval_state.find('evr')
					oval_state_version = oval_state.find('version')
					oval_state_signature = oval_state.find('signature_keyid')

					# tests of package version
					if oval_state_evr is not None:
						if oval_state_evr.attrib['operation'] == 'less than':
							result = True
							self.product = pkg_name
							self.fixed_version = oval_state_evr.text
						else:
							raise RuntimeError("Unknown operation in state:" + oval_state.attrib['id'])

					# tests of rpm signatures
					elif oval_state_signature is not None:
						if oval_state_signature.attrib['operation'] == 'equals':
							# result = self.check_signature(pkg_sig, oval_state_signature.text)
							result = True
						else:
							raise RuntimeError("Unknown operation in state:" + oval_state.attrib['id'])

					# tests of release version
					elif oval_state_version is not None:
						if oval_state_version.attrib['operation'] == 'pattern match':
							oval_state_version_pattern = oval_state_version.text
							#re_match = re.match(oval_state_version_pattern, pkg_ver)
							re_match = re.match(oval_state_version_pattern, self.major_release + '-')
							if re_match is None:
								result = False
							else:
								result = True
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
		return result


if __name__ == '__main__':
	rh = RedHat_Base('7')
	rh.run()

	rh = RedHat_Base('6')
	rh.run()
