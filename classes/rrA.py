#!/usr/bin/env python

class rrA:
	def __init__(self, aa, rr, ttl, qclass, answer):
		self.data = {
				'aa': aa,
				'rr': rr,
				'ttl': ttl,
				'qclass': qclass,
				'type_name': 'A',
				'qtype': 1,
				'answer': answer
			}
		#self.aa = aa
		#self.rr = rr
		#self.ttl = ttl
		#self.qclass = qclass
		#self.qtype = 'A'
		#self.answer = answer

	def printargs(self):
		print self['aa']
		print self['rr']
		print self['ttl']
		print self['qclass']
		print self['type_name']
		print self['qtype']
		print self['answer']

	def __del__(self):
		del self.data

	def __getitem__(self, name):
		if isinstance(name, str):
			if name in self.data:
				return self.data[name]
			else:
				raise KeyError('NonExistentItem')
		else:
			return None
