#!/usr/bin/env python
#encoding=utf8

import os
import sys
import pdb
import sqlite3
from datetime import datetime

res_path = os.path.dirname(os.path.abspath(__file__)) + '/../res/'
vul_data_db_path = res_path + '/db/vul_data.sqlite'


class DB_CVE:
	def __del__(self):
		self.conn.close()

	def __init__(self, init=False):
		self.conn = sqlite3.connect(vul_data_db_path)
		self.conn.execute('pragma journal_mode=wal;')
		self.cursor = self.conn.cursor()
		if init:
			self.cursor.execute('delete from cve')
			self.conn.commit()


	def insert(self, cve_id, date, cwe, score, access_vector, access_complexity, authentication,
									confidentiality_impact, integrity_impact, availability_impact, cpe, summary, poc, commit=False):

		self.cursor.execute('INSERT INTO cve '
							'VALUES(?,?,?,?,?,?,?,?,?,?,?,?, ?)',
								(cve_id, date, cwe, score, access_vector, access_complexity, authentication,
									confidentiality_impact, integrity_impact, availability_impact, cpe, summary, poc))

	def get_by_id(self, cve_id):
		self.cursor.execute('select * from cve where id=?', (cve_id,))
		return self.cursor.fetchall()

	def get_by_cpe(self, cpe):
		self.cursor.execute('select * from cve where cpe like ?', ('%' + cpe + '%',))
		return self.cursor.fetchall()

	def commit(self):
		self.conn.commit()

	def update_exp(self, cve_id, exp_id, commit=False):
		self.cursor.execute('update cve set poc=? where id=?', (exp_id, cve_id))
		if commit:
			self.commit()


class DB_third_party_soft_cve:
	def __del__(self):
		self.conn.close()

	def __init__(self, init=False):
		self.conn = sqlite3.connect(vul_data_db_path)
		self.conn.execute('pragma journal_mode=wal;')
		self.cursor = self.conn.cursor()
		if init:
			self.cursor.execute('delete from third_party_soft_cve')
			self.commit()
	def insert(self, package, affected_ver, cveid, commit=False):
		self.cursor.execute('insert into third_party_soft_cve values (?,?,?)', (package, affected_ver, cveid))
		if commit:
			self.commit()

	def clear(self, package=None):
		if package is None:
			self.cursor.execute('delete from third_party_soft_cve')
		else:
			self.cursor.execute('delete from third_party_soft_cve where package=?', (package,))

		self.commit()

	def commit(self):
		self.conn.commit()

class DB_OVAL:
	def __del__(self):
		self.commit()
		self.conn.close()

	def __init__(self, distro=None, release=None):
		self.conn = sqlite3.connect(vul_data_db_path)
		self.conn.execute('pragma journal_mode=wal;')
		self.cursor = self.conn.cursor()
		if distro is not None and release is not None:
			self.cursor.execute('delete from oval where distro=? and release=?', (distro, release))
			self.conn.commit()

	def insert(self, distro, release, title, title_detailed, package, fixed_version, severity, date, cve, desc, ref):
		try:
			self.cursor.execute('insert into oval values(?,?,?,?,?,?,?,?,?,?, ?)',
						(distro, release, title, title_detailed, package, fixed_version, severity, date, cve, desc ,ref)
						)
		except Exception,e:
			print repr(e)
			pdb.set_trace()

	def commit(self):
		self.conn.commit()


def get_info_for_3rd_soft_cve(db, cve):
	result = db.get_by_id(cve)
	if len(result) == 0:
		return False
	else:
		result = result[0]
	score = result[3]
	poc = result[12]
	access_complexity = result[5]
	date = result[1]
	desc = result[11]
	if score >9 or poc is not None:
		severity = "critical"
	elif score > 8 and access_complexity == 'LOW':
		severity = "important"
	elif score >= 5.5:
		severity = "moderate"
	else:
		severity = "low"

	return severity, date, desc
