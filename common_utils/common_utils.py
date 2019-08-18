#!/usr/bin/env python
#encoding=utf8

# @author: King's Way <io@stdio.io>
# @created: 2016.08 ~ 2018.05


import os
import sys
import types
from subprocess import Popen, PIPE
try:
	import xml.etree.cElementTree as ET
except ImportError:
	import xml.etree.ElementTree as ET


def strip_namespaces(tree):
	"""Remove all namespaces from tags and attributes in XML.
		Leaves only the local names in the subtree.
	"""
	for i in tree.iter():
		tag = i.tag
		if tag and isinstance(tag, str) and tag[0] == '{':
			i.tag = tag.partition('}')[2]
		attrib = i.attrib
		if attrib:
			for name, value in list(attrib.items()):
				if name and isinstance(name, str) and name[0] == '{':
					del attrib[name]
					attrib[name.partition('}')[2]] = value
	return tree


def get_element_text(obj):
	try:
		if obj is None:
			return "Null"
		elif obj.text is None:
			return "Null"
		else:
			return obj.text
	except TypeError:
		return "Null"


def run_cmd(cmd, shell=False):
	# if cmd is a String, then we transform it into a list
	if isinstance(cmd, types.StringType) and shell == False:
		cmd = cmd.split()
	try:
		p = Popen(cmd, stderr=PIPE, stdout=PIPE, shell=shell)
		out, err = p.communicate()
		returncode = p.returncode
		if err:
			# sys.stderr.write('Error when running cmd:' + str(cmd) + '\n' + err)
			out = err + out + '\t' + str(cmd)
		p.wait()
	except OSError, e:
		returncode = -1
		out = str(e) + '\t' + str(cmd)
	return returncode, out.strip()


def read_xml(filename, flag='oval'):
	if flag == 'oval':
		res_path = os.path.dirname(os.path.abspath(__file__)) + '/../res/oval/'
		if not os.path.exists(res_path + filename):
			# the file does not exist yet or need update
			raise RuntimeError('File not existed:' + filename)

	elif flag == 'cve':
		res_path = os.path.dirname(os.path.abspath(__file__)) + '/../res/cve/'
		if not os.path.exists(res_path + filename):
			raise RuntimeError('File not existed:' + filename)
	else:
		raise RuntimeError('Not supported flag argument in read_xml()')

	# strip the namespaces in xml files
	if not os.path.exists(res_path + filename + '_stripped'):
		tree = strip_namespaces(ET.parse(res_path + filename))
		tree.write(res_path + filename + '_stripped', encoding='UTF-8')
		del tree

	return ET.parse(res_path + filename + '_stripped')
