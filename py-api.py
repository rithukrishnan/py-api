#!/usr/bin/env python3
#
# GX PYTHON API for NETCONF requests
# Author: Rithu Anand Krishnan
#    
#
from ncclient import operations
from ncclient import manager, xml_
import xml.etree.ElementTree as ET
import os
import socket
import time

class PyAPI:

	nsmap = {'ne' : 'http://company/yang/ioa/ne'}

	def __init__(self, ip, user, password, port=830, verbose=False):
		"""
        Constructor for PyAPI
        :param user: credentials
        :param password: credentials
        :param ip: IP for connection (default value is CRAFT IP)
        :param port: NETCONF Port
        :param verbose: whether to enable verbose mode
		"""
		self.ip = ip
		self.user = user
		self.password = password
		self.port = port
		self.nc = None
		self.verbose = verbose

	@classmethod 
	def create_obj(cls, user, password, ip="169.254.0.1", port=830, verbose=False):
		"""
		This is a class method (User need not make a call to this method explicitly) 
		Return object if validation passes, else return None.
		"""
		if (cls.validate_ip4(cls,ip) or cls.validate_ip6(cls,ip)):
			myObj = cls(ip, user, password, port, verbose)
			return myObj
		else:
			print("ERROR: IP format not supported")
			return None

	def validate_ip4(self, ip):
		"""
		Verify if ip is in ipv4 format
		"""
		try:
			socket.inet_pton(socket.AF_INET, ip)
		except AttributeError:  # no inet_pton here, sorry
			try:
				socket.inet_aton(ip)
			except socket.error:
				return False
		except socket.error:  # not a valid address
			return False

		return True

	def validate_ip6(self, ip):
		"""
		Verify if ip is in ipv6 format
		"""
		try:
			socket.inet_pton(socket.AF_INET6, ip)
		except socket.error:  # not a valid address
			return False
		return True
		
	def connect(self):
		"""
			API to establish a connection with the box.
		"""
		self.nc = manager.connect(host=self.ip,
							 port=self.port, 
							 username=self.user,
                    		 password=self.password,
							 hostkey_verify=False)
		self.nc._raise_mode=0

	def set_raise_mode(self, mode):
		"""
			API to set raise mode value.
			:param mode: Mode value
		"""
		assert (mode in (operations.RaiseMode.NONE, operations.RaiseMode.ERRORS, operations.RaiseMode.ALL)), "Invalid value for mode."
		self.nc._raise_mode=mode

	def get_current_swversion(self):	
		"""
			To get information about current software
			running on box
		"""
		result = self.nc.get(('xpath', "//sw-management/software-load[swload-state='active']"))
		return result.data.find(".//ne:swload-version", namespaces=PyAPI.nsmap).text


	def subscribe(self, subtree=None, stream=None, starttime=None, stoptime=None, wait_and_print=False):
		"""
		Subscribe to NETCONF notifications
		:param subtree: if present, defines a filter for the subscription
		:param stream: The event stream to subscribe to
		:param starttime: When replaying notifications, the earliest notifications to replay. eg 2021-11-09T04:08:09Z
		:param stoptime: When replaying notifications, the latest notifications to replay. eg 2021-11-09T04:08:09Z
		:param wait_and_print: if True, will block on this method, printing all received notifications; otherwise, will return immediately
		"""
		if subtree is None:
			# When subtree is not mentioned.
			rpc = '''
                <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
                    %s
                    %s
                    %s
                </create-subscription>
			''' % ('' if stream is None else "<stream>%s</stream>" % stream, '' if starttime is None else "<startTime>%s</startTime>" % starttime, '' if stoptime is None else "<stopTime>%s</stopTime>" % stoptime)
			output = self.nc.dispatch(xml_.to_ele(rpc)).xml
			if "rpc-error" in output:
					print("Subscribe failed!")
					print(output)
					return output
		else:
			# ncclient API currently doesn't support filtered subscriptions
			# manually create the request
			rpc = '''
				<create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
					<filter type="subtree">
					%s
					</filter>
					%s
					%s
  					%s
				</create-subscription>
            	''' % (subtree, '' if stream is None else "<stream>%s</stream>" % stream, '' if starttime is None else "<startTime>%s</startTime>" % starttime, '' if stoptime is None else "<stopTime>%s</stopTime>" % stoptime)
			output = self.nc.dispatch(xml_.to_ele(rpc)).xml
			if "rpc-error" in output:
					print("Subscribe failed!")
					print(output)
					return output
 
		while wait_and_print:
			# Forever listening
			print(self.nc.take_notification().notification_xml)
	
	
	def get_notifications(self):
		"""
		Retrieve last received notification in a non-blocking way; may return None if no nothing was received
		:return: last received notification, or None
		"""
		notif = self.nc.take_notification(timeout=2)
		if notif is not None:
			return notif.notification_xml
		return None
	

	def get_subtree(self, subtree):
		"""
		Performs a NETCONF <get> request with a subtree filter
		:param subtree: filter
		:return: xml response
		"""
		return self.nc.get(('subtree', subtree)).xml
 
	def get_xpath(self, xpath):
		"""
		Performs a NETCONF <get> request with a xpath filter
		:param xpath: filter
		:return: xml response
		"""
		return self.nc.get(('xpath', xpath)).xml

	def exit(self):
		"""
        Closes current session
		"""
		output = self.nc.close_session()
		return output
 
	def lock(self):
		"""
        Locks running datastore
		"""
		output = self.nc.lock(target='running')
		return output
 
	def unlock(self):
		"""
		Unlocks running datastore
		"""
		output = self.nc.unlock(target='running')
		return output

	def get_running_config(self):
		"""
		API to get details about current running configurations
		"""
		return self.nc.get_config(source='running', filter=('subtree', "<ne/>")).xml
