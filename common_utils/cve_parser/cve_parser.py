#!/usr/bin/env python
#encoding=utf8

import os
import sys
path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/../../')
sys.path.append(path)

from common_utils.database import DB_CVE
from common_utils.common_utils import read_xml
from common_utils.common_utils import get_element_text as text


class CVE_Parser:
	def __init__(self):
		self.filename = 'nvdcve-2.0-%s.xml'
		self.db = DB_CVE(init=True)
		self.count = 0

	def run(self, years):
		for year in years:
			sys.stdout.write("\nYear:" + year)
			tree = read_xml(self.filename % year, flag='cve')
			self.parse(tree)
		print "\nAll:", self.count

	def parse(self, tree):
		data = []
		for entry in tree.getroot():
			cve_id = text(entry.find('cve-id'))
			date = text(entry.find('published-datetime'))[0:10]
			cwe = self.get_cwe(entry)
			summary = text(entry.find('summary'))
			score, access_vector, access_complexity, authentication, confidentiality_impact, \
			integrity_impact,  availability_impact = self.get_cvss_element(entry)

			cpe = self.get_cpe(entry)
			date = date[0:10]
			poc = None

			# Insert the data first, and then call commit() to write the transaction.
			# This will faster the process quite a lot
			self.db.insert(cve_id, date, cwe, score, access_vector, access_complexity, authentication,
						   confidentiality_impact, integrity_impact, availability_impact, cpe, summary, poc)

			# print cve_id, date, cwe, score, access_vector, access_complexity, authentication,
			# print confidentiality_impact, integrity_impact, availability_impact, cpe, summary
			self.count += 1
		self.db.commit()

	def get_cvss_element(self, entry):
		cvss = entry.find('cvss')
		if cvss is not None:
			bm = cvss.find('base_metrics')
			score = float(text(bm.find('score')))
			access_vector = text(bm.find('access-vector'))
			access_complexity = text(bm.find('access-complexity'))
			authentication = text(bm.find('authentication'))
			confidentiality_impact = text(bm.find('confidentiality-impact'))
			integrity_impact = text(bm.find('integrity-impact'))
			availability_impact = text(bm.find('availability-impact'))
			return [score, access_vector, access_complexity, authentication, confidentiality_impact,
					integrity_impact, availability_impact]
		else:
			return [-1, 'Null', 'Null', 'Null', 'Null', 'Null', 'Null']

	def get_cwe(self, entry):
		cwe = entry.find('cwe')
		if cwe is None:
			return 'Null'
		else:
			try:
				return cwe.attrib['id']
			except KeyError:
				return 'Null'

	def get_cpe(self, entry):
		products_list = entry.find('vulnerable-software-list')
		if products_list is None:
			return 'Null'
		products_list = products_list.findall('product')
		if products_list is None:
			return 'Null'

		products = ''
		flag_mark = False
		for i in products_list:
			if flag_mark:
				products += '||' + (text(i))
			else:
				products += text(i)
				flag_mark = True
		return products


if __name__ == '__main__':

	years = ['2018', '2017', '2016', '2015', '2014', '2013', '2012', '2011', '2010', '2009', '2008']

	cve = CVE_Parser()
	cve.run(years)
