
import socket
import struct

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3

_defaultproxy = None
_orgsocket = socket.socket

class ProxyError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class GeneralProxyError(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Socks5AuthError(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Socks5Error(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Socks4Error(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class HTTPError(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

_generalerrors = ("success",
		   "invalid data",
		   "not connected",
		   "not available",
		   "bad proxy type",
		   "bad input")

_socks5errors = ("succeeded",
		  "general SOCKS server failure",
		  "connection not allowed by ruleset",
		  "Network unreachable",
		  "Host unreachable",
		  "Connection refused",
		  "TTL expired",
		  "Command not supported",
		  "Address type not supported",
		  "Unknown error")

_socks5autherrors = ("succeeded",
		      "authentication is required",
		      "all offered authentication methods were rejected",
		      "unknown username or invalid password",
		      "unknown error")

_socks4errors = ("request granted",
		  "request rejected or failed",
		  "request rejected because SOCKS server cannot connect to identd on the client",
		  "request rejected because the client program and identd report different user-ids",
		  "unknown error")

def setdefaultproxy(proxytype=None,addr=None,port=None,rdns=True,username=None,password=None):
	
	global _defaultproxy
	_defaultproxy = (proxytype,addr,port,rdns,username,password)
	
class socksocket(socket.socket):
	
	
	def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None):
		_orgsocket.__init__(self,family,type,proto,_sock)
		if _defaultproxy != None:
			self.__proxy = _defaultproxy
		else:
			self.__proxy = (None, None, None, None, None, None)
		self.__proxysockname = None
		self.__proxypeername = None
	
	def __recvall(self, bytes):
		
		data = ""
		while len(data) < bytes:
			data = data + self.recv(bytes-len(data))
		return data
	
	def setproxy(self,proxytype=None,addr=None,port=None,rdns=True,username=None,password=None):
		
		self.__proxy = (proxytype,addr,port,rdns,username,password)
	
	def __negotiatesocks5(self,destaddr,destport):
		
		if (self.__proxy[4]!=None) and (self.__proxy[5]!=None):
			
			self.sendall("\x05\x02\x00\x02")
		else:
			
			self.sendall("\x05\x01\x00")
		
		chosenauth = self.__recvall(2)
		if chosenauth[0] != "\x05":
			self.close()
			raise GeneralProxyError((1,_generalerrors[1]))
		
		if chosenauth[1] == "\x00":
			
			pass
		elif chosenauth[1] == "\x02":
			
			self.sendall("\x01" + chr(len(self.__proxy[4])) + self.__proxy[4] + chr(len(self.proxy[5])) + self.__proxy[5])
			authstat = self.__recvall(2)
			if authstat[0] != "\x01":
				
				self.close()
				raise GeneralProxyError((1,_generalerrors[1]))
			if authstat[1] != "\x00":
				
				self.close()
				raise Socks5AuthError,((3,_socks5autherrors[3]))
			
		else:
			
			self.close()
			if chosenauth[1] == "\xFF":
				raise Socks5AuthError((2,_socks5autherrors[2]))
			else:
				raise GeneralProxyError((1,_generalerrors[1]))
		req = "\x05\x01\x00"
		
		try:
			ipaddr = socket.inet_aton(destaddr)
			req = req + "\x01" + ipaddr
		except socket.error:
			if self.__proxy[3]==True:
				ipaddr = None
				req = req + "\x03" + chr(len(destaddr)) + destaddr
			else:
				ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
				req = req + "\x01" + ipaddr
		req = req + struct.pack(">H",destport)
		self.sendall(req)
		
		resp = self.__recvall(4)
		if resp[0] != "\x05":
			self.close()
			raise GeneralProxyError((1,_generalerrors[1]))
		elif resp[1] != "\x00":
			
			self.close()
			if ord(resp[1])<=8:
				raise Socks5Error(ord(resp[1]),_generalerrors[ord(resp[1])])
			else:
				raise Socks5Error(9,_generalerrors[9])
		
		elif resp[3] == "\x01":
			boundaddr = self.__recvall(4)
		elif resp[3] == "\x03":
			resp = resp + self.recv(1)
			boundaddr = self.__recvall(resp[4])
		else:
			self.close()
			raise GeneralProxyError((1,_generalerrors[1]))
		boundport = struct.unpack(">H",self.__recvall(2))[0]
		self.__proxysockname = (boundaddr,boundport)
		if ipaddr != None:
			self.__proxypeername = (socket.inet_ntoa(ipaddr),destport)
		else:
			self.__proxypeername = (destaddr,destport)
	
	def getproxysockname(self):
		
		return self.__proxysockname
	
	def getproxypeername(self):
		
		return _orgsocket.getpeername(self)
	
	def getpeername(self):
		
		return self.__proxypeername
	
	def __negotiatesocks4(self,destaddr,destport):
		
		rmtrslv = False
		try:
			ipaddr = socket.inet_aton(destaddr)
		except socket.error:
			
			if self.__proxy[3]==True:
				ipaddr = "\x00\x00\x00\x01"
				rmtrslv = True
			else:
				ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
		
		req = "\x04\x01" + struct.pack(">H",destport) + ipaddr
		
		if self.__proxy[4] != None:
			req = req + self.__proxy[4]
		req = req + "\x00"
		
		if rmtrslv==True:
			req = req + destaddr + "\x00"
		self.sendall(req)
		
		resp = self.__recvall(8)
		if resp[0] != "\x00":
			
			self.close()
			raise GeneralProxyError((1,_generalerrors[1]))
		if resp[1] != "\x5A":
			
			self.close()
			if ord(resp[1]) in (91,92,93):
				self.close()
				raise Socks4Error((ord(resp[1]),_socks4errors[ord(resp[1])-90]))
			else:
				raise Socks4Error((94,_socks4errors[4]))
		
		self.__proxysockname = (socket.inet_ntoa(resp[4:]),struct.unpack(">H",resp[2:4])[0])
		if rmtrslv != None:
			self.__proxypeername = (socket.inet_ntoa(ipaddr),destport)
		else:
			self.__proxypeername = (destaddr,destport)
	
	def __negotiatehttp(self,destaddr,destport):
		
		if self.__proxy[3] == False:
			addr = socket.gethostbyname(destaddr)
		else:
			addr = destaddr
		self.sendall("CONNECT " + addr + ":" + str(destport) + " HTTP/1.1\r\n" + "Host: " + destaddr + "\r\n\r\n")
		
		resp = self.recv(1)
		while resp.find("\r\n\r\n")==-1:
			resp = resp + self.recv(1)
		
		statusline = resp.splitlines()[0].split(" ",2)
		if statusline[0] not in ("HTTP/1.0","HTTP/1.1"):
			self.close()
			raise GeneralProxyError((1,_generalerrors[1]))
		try:
			statuscode = int(statusline[1])
		except ValueError:
			self.close()
			raise GeneralProxyError((1,_generalerrors[1]))
		if statuscode != 200:
			self.close()
			raise HTTPError((statuscode,statusline[2]))
		self.__proxysockname = ("0.0.0.0",0)
		self.__proxypeername = (addr,destport)
	
	def connect(self,destpair):
		
		if (type(destpair) in (list,tuple)==False) or (len(destpair)<2) or (type(destpair[0])!=str) or (type(destpair[1])!=int):
			raise GeneralProxyError((5,_generalerrors[5]))
		if self.__proxy[0] == PROXY_TYPE_SOCKS5:
			if self.__proxy[2] != None:
				portnum = self.__proxy[2]
			else:
				portnum = 1080
			_orgsocket.connect(self,(self.__proxy[1],portnum))
			self.__negotiatesocks5(destpair[0],destpair[1])
		elif self.__proxy[0] == PROXY_TYPE_SOCKS4:
			if self.__proxy[2] != None:
				portnum = self.__proxy[2]
			else:
				portnum = 1080
			_orgsocket.connect(self,(self.__proxy[1],portnum))
			self.__negotiatesocks4(destpair[0],destpair[1])
		elif self.__proxy[0] == PROXY_TYPE_HTTP:
			if self.__proxy[2] != None:
				portnum = self.__proxy[2]
			else:
				portnum = 8080
			_orgsocket.connect(self,(self.__proxy[1],portnum))
			self.__negotiatehttp(destpair[0],destpair[1])
		elif self.__proxy[0] == None:
			_orgsocket.connect(self,(destpair[0],destpair[1]))
		else:
			raise GeneralProxyError((4,_generalerrors[4]))
