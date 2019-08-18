#!/usr/bin/env python
#encoding=utf8

import re
import os
import sys
path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/../')
sys.path.append(path)
from common_utils.database import DB_OVAL
from common_utils.common_utils import read_xml
from common_utils.common_utils import get_element_text as text

try:
	import xml.etree.cElementTree as ET
except ImportError:
	import xml.etree.ElementTree as ET


class Ubuntu_Check:
	def __init__(self, release):
		self.filename = 'com.ubuntu.%s.cve.oval.xml'

		self.oval_generator = None
		self.oval_definitions = None
		self.oval_tests = None
		self.oval_objects = None
		self.oval_states = None

		# we set a global var 'product' to get the name of the vulnerable package currently being checked
		# Cause ubuntu definitions do noe provide us with the product name .... F**K ubuntu....x1
		self.product = ''
		self.fixed_version = ''
		self.release = release
		self.db = DB_OVAL('ubuntu', release)

		self.init()

	def init(self):
		if self.release == '18.04':
			release = 'bionic'
		elif self.release == '16.04':
			release = 'xenial'
		elif self.release == '14.04':
			release = 'trusty'
#		elif self.release == '12.04':
#			release = 'precise'
		else:
			raise RuntimeError("Version: Ubuntu %s is not supported" % self.release)

		tree = read_xml(self.filename % release)

		self.oval_generator = tree.getroot().getchildren()[0]
		self.oval_definitions = tree.getroot().getchildren()[1]
		self.oval_tests = tree.getroot().getchildren()[2]
		self.oval_objects = tree.getroot().getchildren()[3]
		self.oval_states = tree.getroot().getchildren()[4]
		del tree

	def run(self):
		self.do_run()

	def do_run(self):
		count = 0
		# delete the first element in oval_definitions, cause it always be 'class="inventory"'
		if self.oval_definitions[0].attrib['class'] == "inventory":
			del self.oval_definitions[0]

		for i in self.oval_definitions:
			oval_metadata = i.find('metadata')
			oval_criteria = i.find('criteria')
			oval_advisory = oval_metadata.find('advisory')
			try:
				title = oval_metadata.find('title')
				severity = oval_advisory.find('severity')
				date = oval_advisory.find('public_date')
				description = oval_metadata.find('description')
				reference = oval_metadata.find('reference')
				if reference is None:
					cve = None
				else:
					cve = reference.attrib['ref_id']
			except AttributeError, e:
				print
				print Fore.YELLOW + str(e) + " AttributeError! definition id: " + i.attrib['id']

			refs = oval_advisory.findall('ref')
			ref = []
			for _ref in refs:
				ref.append(text(_ref))

			# in ubuntu definitions, some may do not have these elements.....F**K ubuntu....x3
			title = text(title)
			severity = text(severity)
			date = text(date)
			description = text(description)

			result = self.check(oval_criteria)
			if result:
				count += 1
				if count % 1000 == 0:
					self.db.commit()
				print "Insert:", count

				title_detailed = title
				if cve is not None:
					title = cve
				else:
					title = title.split()[0]

				severity = self.handle_severity(severity)
				self.db.insert('ubuntu', self.release, title, title_detailed, self.product, self.fixed_version, severity, date, cve, description,'||'.join(ref))
			else:
				# print(Fore.BLUE + "OK"), title
				pass
		self.db.commit()

	def check(self, element):
		# print "run_check: " + element.attrib['comment'] + "    " + str(element.tag == 'criterion')
		if element is None:
			return False
		# For ubuntu, there is always an extend_definition to check the system release version
		elif element.tag == 'extend_definition':
			return True
		elif element.tag == 'criterion':
			return self.do_check(element)

		elif element.tag == 'criteria':
			# For ubuntu, the highest level of criteria does not have any attributes,
			# so we assume the attrib['operator'] is 'AND'
			if len(element.attrib) == 0:
				element.attrib['operator'] = 'AND'

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
					if result:
						break
				return result
			else:
				raise RuntimeError("no operator within criteria: " + str(element.attrib))

	def do_check(self, criterion):
		# print "do check:", criterion.attrib['test_ref'],
		result = False
		# First, get the element by id
		oval_test = self.oval_tests.find("*[@id='%s']" % criterion.attrib['test_ref'])

		oval_object = None
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
			# family_test and uname_test are only to check the system release, return true directly
			if oval_test.tag == 'family_test':
				result = True
			elif oval_test.tag == 'uname_test':
				result = True
			# uknown_test is related to those unclear problems, there is not a clear way to handle this oval definitions.
			elif oval_test.tag == 'unknown_test':
				result = False

			# if the test is 'textfilecontent_test'
			elif oval_test.tag == 'textfilecontent_test':
				result = True
#				oval_path = oval_object.find('path').text
#				oval_filename = oval_object.find('filename').text
#				file_text = self.sysinfo['config']['files'][oval_path + '/' + oval_filename]
#
#				oval_object_line = oval_object.find('line')
#				if (oval_object_line is not None) and oval_object_line.attrib['operation'] == 'pattern match':
#					oval_pattern = oval_object_line.text
#					re_match = re.match(oval_pattern, file_text)
#					if re_match is None:
#						result = False
#					else:
#						file_text = re_match.group()
#						oval_state_line = oval_state.find('line')
#						if oval_state_line is not None:
#							if oval_state_line.attrib['operation'] == 'equals':
#								result = file_text == oval_state_line.text
#							# there may be other operations in the future
#							else:
#								# return False
#								raise RuntimeError("Unknown operation in state:" + oval_state.attrib['id'])
#						else:
#							# return False
#							raise RuntimeError("element 'line' not found in state:" + oval_state.attrib['id'])
#				else:
#					raise RuntimeError('Unknown operation in oval_object_line:' + oval_object.attrib['id'])

			# if the test is 'dpkginfo_test'
			elif oval_test.tag == 'dpkginfo_test':
				pkg_name = oval_object.find('name').text
#				pkg_ver = None
#
#				# the package name in oval is always the source package
#				# so, if there is no such a package in the binary packages, we have to go through the source packages
#				pkg_exist_flag = False
#
#				if pkg_name in self.sysinfo['pkgs']:
#					pkg_ver = self.sysinfo['pkgs'][pkg_name][2]
#					pkg_exist_flag = True
#				else:
#					# For the source packages, there may be more than one binary package name
#					# Such as the kernel package (named linux-image-xxx) in debian-based distributions
#
#					# The first solution is sort with multiple keywords
#					# This will not be 100% accurate, cause it sorts by character order
#					# rows = self.sysinfo['pkgs'].values()
#					# rows.sort(key=lambda x:(x[3], x[1]))
#
#					# The second solution is to go through the whole list every time...
#					for pkg in self.sysinfo['pkgs'].values():
#						pkg_src_name = pkg[3]
#						if pkg_src_name == pkg_name:
#							if not pkg_exist_flag:
#								pkg_exist_flag = True
#								pkg_ver = pkg[2]
#							# if we have already found the package and now get a newer version
#							elif self.is_less_than(pkg_ver, pkg[2]):
#								pkg_ver = pkg[2]
#							else:
#								pass
#
#				# if the package and source package do not exist, return False directly
#				if not pkg_exist_flag:
#					result = False

				# In ubuntu oval definitions, if the package exists, but there is no oval_state,
				# then it means we only need to check the existence of the package.
				# But it doesn't mean the package is vulnerable.
				# It also covers this situation: if oval_test.attrib['check_existence'] == 'any_exist': return True

				# Whatever, we alwaysreturn false to make our check process work normally.
				# And, F**K Ubuntu!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! x2

				# if the package exists, but there is no oval_state
				if oval_state is None:
					result = False

				# if the package exists, then
				# recheck the state tag is 'dpkginfo_state'
				elif oval_state.tag == 'dpkginfo_state':
					# [debian/ubuntu/red hat] for those tests of package version, the child element is <evr>
					# [red hat] for those tests of signature, the child element is <signature_keyid>
					# [red hat] for those tests of release version, the child element is <version>
					oval_state_evr = oval_state.find('evr')

					if oval_state_evr is not None:
						if oval_state_evr.attrib['operation'] == 'less than':
							result = True
							#result = self.is_less_than(ver1=pkg_ver, ver2=oval_state_evr.text, product=pkg_name)
							self.product = pkg_name
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
		return result

	def handle_severity(self, severity):
		if severity == "Critical":
			return "critical"
		elif severity == 'High':
			return "important"
		elif severity == 'Medium':
			return "moderate"
		else:
			return "low"

if __name__ == '__main__':
	ub = Ubuntu_Check('14.04')
	ub.run()

	ub = Ubuntu_Check('16.04')
	ub.run()

	ub = Ubuntu_Check('18.04')
	ub.run()
