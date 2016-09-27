
#---------------------------------------------------------------------------- BaseHTTPServer Code Starts------------------------------------------------------------------------------------------------#

"""HTTP server base class.

Note: the class in this module doesn't implement any HTTP request; see
SimpleHTTPServer for simple implementations of GET, HEAD and POST
(including CGI scripts).  It does, however, optionally implement HTTP/1.1
persistent connections, as of version 0.3.

Contents:

- BaseHTTPRequestHandler: HTTP request handler base class
- test: test function

XXX To do:

- log requests even later (to capture byte count)
- log user-agent header and other interesting goodies
- send error log to separate file
"""


# See also:
#
# HTTP Working Group                                        T. Berners-Lee
# INTERNET-DRAFT                                            R. T. Fielding
# <draft-ietf-http-v10-spec-00.txt>                     H. Frystyk Nielsen
# Expires September 8, 1995                                  March 8, 1995
# Modification Python Data  		       	    P.Susanth , On January 12, 2011
#
# URL: http://www.ics.uci.edu/pub/ietf/http/draft-ietf-http-v10-spec-00.txt
#
# and
#
# Network Working Group                                      R. Fielding
# Request for Comments: 2616                                       et al
# Obsoletes: 2068                                              June 1999
# Category: Standards Track
# Mode of Access Dynamic Data writer   		P.Susanth , On January 20, 2011
#
# URL: http://www.faqs.org/rfcs/rfc2616.html

# Log files
# ---------
#
# Here's a quote from the NCSA httpd docs about log file format.
#
# | The logfile format is as follows. Each line consists of:
# |
# | host rfc931 authuser [DD/Mon/YYYY:hh:mm:ss] "request" ddd bbbb
# |
# |        host: Either the DNS name or the IP number of the remote client
# |        rfc931: Any information returned by identd for this person,
# |                - otherwise.
# |        authuser: If user sent a userid for authentication, the user name,
# |                  - otherwise.
# |        DD: Day
# |        Mon: Month (calendar name)
# |        YYYY: Year
# |        hh: hour (24-hour format, the machine's timezone)
# |        mm: minutes
# |        ss: seconds
# |        request: The first line of the HTTP request as sent by the client.
# |        ddd: the status code returned by the server, - if not available.
# |        bbbb: the total number of bytes sent,
# |              *not including the HTTP/1.0 header*, - if not available
# |
# | You can determine the name of the file accessed through request.
#
# (Actually, the latter is only true if you know the server configuration
# at the time the request was made!)






__version__ = "0.3"

__all__ = ["HTTPServer", "BaseHTTPRequestHandler"]




import sys
import webbrowser
import os
import time
import socket # For gethostbyaddr()
from warnings import filterwarnings, catch_warnings
with catch_warnings():
    if sys.py3kwarning:
        filterwarnings("ignore", ".*mimetools has been removed",
                        DeprecationWarning)
    import mimetools
import SocketServer
#Folder Creating for Service
cwd=os.getcwd()
path=os.getcwd()+'/backbone/' # don't erase this bcoz its used in below coding many times.....
def self_create_folders():
	try:
		if ('backbone') not in os.listdir(cwd):
			os.mkdir(cwd+'/backbone')
		if ('user') not in os.listdir(cwd+'/backbone'):
			os.mkdir(cwd+'/backbone/user')
		if ('sync') not in os.listdir(cwd+'/backbone'):
			os.mkdir(cwd+'/backbone/sync')
		if ('server') not in os.listdir(cwd+'/backbone'):
			os.mkdir(cwd+'/backbone/server')
		if ('universal') not in os.listdir(cwd+'/backbone/sync'):
			os.mkdir(path+'/sync/'+'universal')
		if ('personal') not in os.listdir(cwd+'/backbone/sync'):
			os.mkdir(path+'/sync/'+'personal')
		if ('old_Files') not in os.listdir(cwd+'/backbone/sync'):
			os.mkdir(path+'/sync/'+'old_Files')
		if ('Susanth_._Physics') not in os.listdir(cwd+'/backbone/sync/universal'):
			os.mkdir(path+'/sync/universal/'+'Susanth_._Physics')
		if ('Susanth_._Mathematics') not in os.listdir(cwd+'/backbone/sync/universal'):
			os.mkdir(path+'/sync/universal/'+'Susanth_._Mathematics')
		if ('Susanth_._English') not in os.listdir(cwd+'/backbone/sync/universal'):
			os.mkdir(path+'/sync/universal/'+'Susanth_._English')
		if ('Susanth_._PDS') not in os.listdir(cwd+'/backbone/sync/universal'):
			os.mkdir(path+'/sync/universal/'+'Susanth_._PDS')
		if ('Susanth_._MP') not in os.listdir(cwd+'/backbone/sync/universal'):
			os.mkdir(path+'/sync/universal/'+'Susanth_._MP')
		if ('forums') not in os.listdir(cwd+'/backbone/user'):
			os.mkdir(cwd+'/backbone/user/forums')
		if ('topics') not in os.listdir(cwd+'/backbone/user/forums'):
			os.mkdir(cwd+'/backbone/user/forums/topics')
		if ('histories') not in os.listdir(cwd+'/backbone/user'):
			os.mkdir(cwd+'/backbone/user/histories')
		if ('images') not in os.listdir(cwd+'/backbone/user'):
			os.mkdir(cwd+'/backbone/user/images')
		if ('photoes') not in os.listdir(cwd+'/backbone/user/images'):
			os.mkdir(cwd+'/backbone/user/images/photoes')
		if ('background') not in os.listdir(cwd+'/backbone/user/images'):
			os.mkdir(cwd+'/backbone/user/images/background')
		if ('default_photo') not in os.listdir(cwd+'/backbone/user/images/photoes'):
			os.mkdir(cwd+'/backbone/user/images/photoes/default_photo')
		
	except:OSError





def self_create_user_photo():
	# Program that create a anolog clock with current time & displaying to the user
	# By P.Susanth 10July,2011
	import time,Image,ImageDraw,os
	def anolog_box(rmax,perc):
		sub=rmax*perc/100
		return (rmax-sub,rmax-sub,rmax+sub,rmax+sub)
	r=350
	img=Image.new('RGB',(r*2,r*2),color=(128,128,128))
	draw=ImageDraw.Draw(img)
	draw.pieslice(anolog_box(r,100),0,360,fill=(0,0,0))
	draw.pieslice(anolog_box(r,98),0,360,fill=(80,80,255))
	draw.pieslice(anolog_box(r,94),0,360,fill=(0,0,0))
	draw.pieslice(anolog_box(r,93),0,360,fill=(255,255,255))
	for i in range(12):
		deg=i*30
		draw.pieslice(anolog_box(r,90),deg-1,deg+1,fill=(0,0,0))
	draw.pieslice(anolog_box(r,75),0,360,fill=(255,255,255))
	now=time.localtime(time.time())
	hour=now[3]%12
	minute=now[4]
	hdeg=hour*30+minute/2
	mdeg=minute*6
	draw.pieslice(anolog_box(r,50),hdeg-4,hdeg+4,fill=(100,100,100))
	draw.pieslice(anolog_box(r,85),mdeg-2,mdeg+2,fill=(100,100,100))
	img.rotate(90).save(os.getcwd()+'/backbone/user/images/photoes/current_time.gif')
try:
	if 'updates.txt' not in os.listdir('backbone/server'):
		r=open('backbone/server/updates.txt','w')
		r.write('This site is constructed by Python High Lever Programming Language')
		r.close()
	if 'day_special.txt' not in os.listdir('backbone/server'):
		s=open('backbone/server/day_special.txt','w')
		s.close()
	if 'quotes.txt' not in os.listdir('backbone/server'):
		q=open('backbone/server/quotes.txt','w')
		q.write('The Knowledge is Power_'+time.strftime('%d/%m/%Y'))
		q.close()
	if 'downloads_members.txt' not in os.listdir('backbone/server'):
		a=open("backbone/server/downloads_members.txt",'a'),a.close()
except:OSError
def self_create_files():
	# data files creating automatically
	a=open('index.html','w')
	a.close()
	try:
		if 'visits_counter.txt' not in os.listdir(path+'/user'):
			b=open('backbone/user/visits_counter.txt','a'),b.close()
		if 'server_ipport.txt' not in os.listdir('backbone/server'):
			sf=open('backbone/server/server_ipport.txt','a'),sf.close()
		if 'ip_users.txt' not in os.listdir('backbone/server'):
			ipu=open('backbone/server/ip_user.txt','a'),ipu.close()
	except:OSError
self_create_files()
current_forum_users=[]
current_hfs_users=[]


#Automatically delete negation files
def self_delete_negation_files(cwd):
 	List=os.listdir(cwd)
	for i in List:
		path=os.path.join(cwd,i)
		try:
			if os.path.isfile(path):
				if i[-1] == '~':
					os.remove(path)
			else:
				self_delete_negation_files(path)
		except:OSError
self_delete_negation_files(cwd)


def user_existance_control():
	# Author: Pangi Susanth
	# Description: This is a program for usernames & ips control
	d = {}
	f=open("backbone/server/ip_user.txt",'a')    # Creating a txt file which  does not exist
	f.close()
	f = open("backbone/server/ip_user.txt",'r')
	r = f.readlines()
	f.close()
	for i in r:					# Coping data from the file to the dictionary
		cont = i.split(':')
		d[cont[1][:-1]] = cont[0]
	keys=d.keys()
	values=d.values()

	def convert(number):		# Convert a string into integer
		try:	
			number1 = int(number)
		except ValueError:
			number1 = 0
		return number1

	def add_new():				# Adding a new user
		new_user = raw_input("\tenter new username : ")
		user=new_user
		try:
			user=user[0].upper()+user[1::].lower()
		except:pass
		def userf(user):
			if user in d:
				print '\n\tusername already existed.\n\ti.e (',user,':',d[user],')\tplease try another.'
				add_new()
		userf(user)
		while (len(user)==0) or (user[0]==' ') or (user[0]=='\t') or (user=='\n') or (user==''):
			print '\tinvalid username....try again...'
			user = raw_input("\tenter new user name : ")
			#computer science and engineering...computer science and engineering..please save the most useful compare the most useful things like one of the most useful things like one 
			#sudo nautilus things like one of the jacksullly please save the most useful things like one of the mP{]
			#Please vaeth contempararily....
			#Computer System One of the most useful things like one of the most useful things like 
			try:
				userf(user[0].upper()+user[1::].lower())
			except:pass		
		ip=raw_input('\tenter new ip: ')
		def ipf(ip):
			if ip in values:
				for i in range(len(values)):
					if values[i]==ip:
						name=keys[i]
				print '\n\tip already existed.\n\ti.e (',name,':',ip,')\t please try another'
		ipf(ip)
		while (len(ip)<7) or (ip in values) or (ip==' ') or (ip==0) or (type(ip)==int) or (ip.count('.')!=3):
			print '\tinvalid ip....try again'
			ip = raw_input('\tenter new ip : ')
			ipf(ip)
		d[user] = ip
		f = open("backbone/server/ip_user.txt",'a')
		f.write(ip+':'),f.write(user),f.write('\n')
		f.close()
		print '\tusername & ip  successfully added !'
	
	def search():		# Searching a user
		user = raw_input('\tenter the username to search:')
		user=user[0].upper()+user[1::].lower()
	 	c = 0
		new = []
		if len(user) != 0:
			for i in d:
				if i.startswith(user):
					new.append(i)
					c = c+1
		if c != 0:
			print '\t',c,'user found............\n'
			print '\t','='*60,'\n'
			for j in new:
				print '\t',j,'\t\t',d[j]
			print '\n\t','='*60
		else:
			print '\tuser not found.'

		

	def delete_user():   # to delete a user
		user_del = raw_input('\tenter the username to delete : ')
		user=user_del
		if user in d:
			del d[user]
			f = open("backbone/server/ip_user.txt",'w')
			for i in d:
				f.write(i+':'),f.write(d[i]),f.write('\n')
			print '\tuser [',user_del,'] successfully deleted..!'
		else:
			print '\tuser not found..?'


	def delete_all_user():		# To delete all user
		f = open("backbone/server/ip_user.txt",'w')
		d.clear()
		print '\tall usernames & ips successfully deleted ..!'


	def edit():			# To edit a user
		name = raw_input('\tenter the username to edit:')
		try:
			name=name[0].upper()+name[1::].lower()
		except:pass
		if name in d:
			print "\tenter 'i' to change the ip\n\tenter 'u' to change the username\n\tenter 'e' to exit"
			new = d[name]
			option = raw_input('\tenter the option : ').lower()
			if option == 'i':
				print '\tolder ip : ',d[name] 
				ip = raw_input('\tenter new ip : ')
				def ipf(ip):
					if ip in values:
						for i in range(len(values)):
							if values[i]==ip:
								name=keys[i]
						print '\n\tip already existed.\n\ti.e (',name,':',ip,')\t please try another'
						edit()
				ipf(ip)
				while (len(ip)<7) or (ip==' ') or (ip==0) or (type(ip)==int) or ip.count('.')!=3:
					print '\tinvalid ip...try again.'
					ip = raw_input('\tenter valid ip : ')
					ipf(ip)
				if len(ip)!=0:
					new=ip
					print '\tnew ip address is : ',ip
					print '\tip changed successfully.'
					print '='*80
					print '\told ip address ------> new ip address'
					print '\t',d[name],'		           ',ip
					print '='*80
				else:
					print '\n\tip not entered..................'
				d[name] = new
				f = open("backbone/server/ip_user.txt",'w')
				for i in d:
					f.write(d[i]+':'+i),f.write('\n')
			elif option == 'u':
				d1={}
				ip=d[name]
				d1[ip]=name
				print '\tolder username : ',d1[ip]
				user = raw_input('\tenter new username : ')
				try:
					user=user[0].upper()+user[1::].lower()
				except:pass
				def userf(user):
					if user in d:
						print '\n\tusername already existed.\n\ti.e (',user,':',d[user],')\tplease try another.'
				userf(user)
				while (len(user)==0) or (user[0]==' ') or (user[0]=='\t') or (user=='\n') or (user==''):
					print '\tinvalid username....try again...'
					user = raw_input("\tenter new username : ")
					try:
						userf(user[0].upper()+user[1::].lower())
					except:pass	
				if len(user)!=0:
					new=user
					print '\tnew username is : ',user
					print '\tusername changed successfully.'
					print '='*80
					print '\tolder username   ------> new username address'
					print '\t',d1[ip],'		           ',user
					print '='*80
					f = open("backbone/server/ip_user.txt",'w')
				else:
					print '\tusername not entered..................'
				del d[name]
				d[new]=ip
				for i in d:
					f.write(d[i]+':'+i),f.write('\n')
			elif option=='e':
				print '\tyour exited'
			else:
				print '\tsorry, your option not in options'
		else:
			print '\tsorry, user not found ..?'


	def see_all():			# To see all user
		print '\n','='*80
		print '\n\t*---- all usernames & ips list  ----*'
		print '\t     ip address |  username'
		print '\t','--'*35
		order = sorted(d)
		c=0
		for i in order:
			c+=1
			print '\t',c,') ',d[i],':',i
		print '\n','='*80

	def menu():
		print '_'*80,'\n\t*----welcome to username & ip control section----*'
		print "\n\tenter '1' to menu\n\tenter '2' to add_user\n\tenter '3' to search user\n\tenter '4' to edit user\n\tenter '5' to see all users\n\tenter '6' to delete user\n\tenter '7' to delete all users\n\tenter '8' to exit."

	menu()
	while True:
		user = raw_input("\n\tenter the major option :")
		user1 = convert(user)  # Calling convert function for conveting the raw_input into integer
		if user1 != 0: 
			if user1==1:
				menu()
			elif user1 == 2:
				add_new()
			elif user1 == 3:
				search()
			elif user1 == 4:
				edit()
			elif user1 == 5:
				see_all()
			elif user1 == 6:
				delete_user()
			elif user1 == 7:
				delete_all_user()
			elif user1==8:
				print '_'*80
				exit()
				self_setup_ip_port()
			else:
				print "\tenter only '8' to exit"
		else:
			print '\n\tinvalid input , try again'


#Server address configuration
PORT=''
IP=''
def self_setup_ip_port():
	def update_ipport(ip,port):
		global IP
		global PORT
		IP=ip
		PORT=port
	
	def ip_port_setup():
		print "\n@-- ADMINISTRATIONS --@\nYOU SHOULD ENTER CORRECT IP & PORT.\nOTHERWISE THIS PROGRAM CANNOT SELF RUN ON YOUR BROWSER\nExample:\nIP:10.4.21.19 (  IP4 CONNECTION METHOD ONLY )\nPORT:2020 ( 4 DIGITS ONLY, FIRST DIGIT IS SHOULD NON-ZERO )\nYOU HAVE TO ENTER THE IP'S & CORRESPONDING NAMES LATER"
		while True:
			new_ip=raw_input('ENTER YOUR SYSTEM IP ADDRESS:')
			if new_ip.count('.')==3:
				break
		while True:
			new_port=raw_input('ENTER A PORT:')
			if len(new_port)==4:
				break
		a=open('backbone/server/server_ipport.txt','w')
		a.write(new_ip+':'+new_port),a.close()
		admin_name=raw_input('YOUR NAME:')
		admin=open('backbone/server/ip_user.txt','w')
		admin.write(new_ip+':'+admin_name),admin.close()
		update_ipport(new_ip,int(new_port))

	#Server address check up
	try:
		if 'server_ipport.txt' not in os.listdir('backbone/server'):
			ss=open('backbone/server/server_ipport.txt','a')
	except:OSError
	server_address=open('backbone/server/server_ipport.txt','r')
	address_read=server_address.read()
	server_address.close()
	if len(address_read)<11:
		ip_port_setup()
	else:
		server_address=open('backbone/server/server_ipport.txt','r')
		address_read=server_address.read()
		server_address.close()			
		ip_port=address_read.split(':')
		# To edit IP & PORT
		print "\nCURRENT SERVER IP & PORT : ",ip_port[0],":",ip_port[1],"\n\tenter 'i' to edit ip\n\tenter 'p' to edit port\n\tenter 'a' to edit address\n\tenter 'u' to edit users control\n\tenter 'd' to run the program\n\tenter 'm' to make limited access member\n\tenter 'e' to exit"
		iput=raw_input(" option : ").lower()
		if iput!='d':
			if iput=='i':
				nip=raw_input('enter your new ip:')
				nd=open('backbone/server/server_ipport.txt','w')
				nd.write(nip+':'+ip_port[1]),nd.close()
				update_ipport(nip,int(ip_port[1]))
			elif iput=='p':
				nport=raw_input('enter new port:')
				nd=open('backbone/server/server_ipport.txt','w')
				nd.write(ip_port[0]+':'+nport),nd.close()
				update_ipport(ip_port[0],int(nport))
			elif iput=='a':
				nip=raw_input('enter your new ip:')
				nport=raw_input('enter new port:')
				nd=open('backbone/server/server_ipport.txt','w')
				nd.write(nip+':'+nport),nd.close()
				update_ipport(nip,int(nport))
			elif iput=='u':
				user_existance_control()
			elif iput=='m':
				try:
					lma=open('backbone/server/limited_members_access.txt','w')
					lma.write('This Mode for Limited Accessibility\nWhich IPs & Names are in ip_name.txt This allow to those users only'),lma.close()
				except:pass
				print 'Done ! Limited Members Access Control Response'
				self_setup_ip_port()
			elif iput=='e':
				exit()
			else:
				print 'I am sorry, I will run the program with previous ip & port'
				update_ipport(ip_port[0],int(ip_port[1]))
		else:
			update_ipport(ip_port[0],int(ip_port[1]))
	#--------------------------------------------------------
# Sockname ip address( socket.py)
def getfqdn(name=''):
    """Get fully qualified domain name from name.

    An empty argument is interpreted as meaning the local host.

    First the hostname returned by gethostbyaddr() is checked, then
    possibly existing aliases. In case no FQDN is available, hostname
    from gethostname() is returned.
    """
    #Changing for know the ip of the accessed user
    name = name.strip()
    if not name or name == '0.0.0.0':
       
    	try:
        	hostname, aliases, ipaddrs = gethostbyaddr(name)
    	except error:
        	pass
    	else:
        	aliases.insert(0, hostname)
        	for name in aliases:
            		if '.' in name:name = hostname
            			
    ip=name
    a=open('backbone/server/ip_user.txt','r')
    b=a.readlines()
    a.close()
    ip_hostname={}
    if len(b)==1:
	for i in b:
		c=i.split(':')
		ip_hostname[c[0]]=c[1]	
    else:
	    for i in b:
		c=i.split(':')
		ip_hostname[c[0]]=c[1][:-1]
# Dictionary for name respective ip address
    if 'limited_members_access.txt' in os.listdir('backbone/server'):
	    if ip in ip_hostname:return ip_hostname[ip] # if the ip in the dictionary then it will show
    else:
	    if ip in ip_hostname:return ip_hostname[ip] # if the ip in the dictionary then it will show
	    else:return ip
	
    



#---------------------------------------------------------



# Default error message template
DEFAULT_ERROR_MESSAGE = """\
<head>
<title>Error response</title>
</head>
<body>
<h1>Error response</h1>
<p>Error code %(code)d.
<p>Message: %(message)s.
<p>Error code explanation: %(code)s = %(explain)s.
</body>
"""

DEFAULT_ERROR_CONTENT_TYPE = "text/html"

def _quote_html(html):
    return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

class HTTPServer(SocketServer.TCPServer):

    allow_reuse_address = 1    # Seems to make sense in testing environment

    def server_bind(self):
        """Override server_bind to store the server name."""
        SocketServer.TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port


class BaseHTTPRequestHandler(SocketServer.StreamRequestHandler):

    """HTTP request handler base class.

    The following explanation of HTTP serves to guide you through the
    code as well as to expose any misunderstandings I may have about
    HTTP (so you don't need to read the code to figure out I'm wrong
    :-).

    HTTP (HyperText Transfer Protocol) is an extensible protocol on
    top of a reliable stream transport (e.g. TCP/IP).  The protocol
    recognizes three parts to a request:

    1. One line identifying the request type and path
    2. An optional set of RFC-822-style headers
    3. An optional data part

    The headers and data are separated by a blank line.

    The first line of the request has the form

    <command> <path> <version>

    where <command> is a (case-sensitive) keyword such as GET or POST,
    <path> is a string containing path information for the request,
    and <version> should be the string "HTTP/1.0" or "HTTP/1.1".
    <path> is encoded using the URL encoding scheme (using %xx to signify
    the ASCII character with hex code xx).

    The specification specifies that lines are separated by CRLF but
    for compatibility with the widest range of clients recommends
    servers also handle LF.  Similarly, whitespace in the request line
    is treated sensibly (allowing multiple spaces between components
    and allowing trailing whitespace).

    Similarly, for output, lines ought to be separated by CRLF pairs
    but most clients grok LF characters just fine.

    If the first line of the request has the form

    <command> <path>

    (i.e. <version> is left out) then this is assumed to be an HTTP
    0.9 request; this form has no optional headers and data part and
    the reply consists of just the data.

    The reply form of the HTTP 1.x protocol again has three parts:

    1. One line giving the response code
    2. An optional set of RFC-822-style headers
    3. The data

    Again, the headers and data are separated by a blank line.

    The response code line has the form

    <version> <responsecode> <responsestring>

    where <version> is the protocol version ("HTTP/1.0" or "HTTP/1.1"),
    <responsecode> is a 3-digit response code indicating success or
    failure of the request, and <responsestring> is an optional
    human-readable string explaining what the response code means.

    This server parses the request and the headers, and then calls a
    function specific to the request type (<command>).  Specifically,
    a request SPAM will be handled by a method do_SPAM().  If no
    such method exists the server sends an error response to the
    client.  If it exists, it is called with no arguments:

    do_SPAM()

    Note that the request name is case sensitive (i.e. SPAM and spam
    are different requests).

    The various request details are stored in instance variables:

    - client_address is the client IP address in the form (host,
    port);

    - command, path and version are the broken-down request line;

    - headers is an instance of mimetools.Message (or a derived
    class) containing the header information;

    - rfile is a file object open for reading positioned at the
    start of the optional input data part;

    - wfile is a file object open for writing.

    IT IS IMPORTANT TO ADHERE TO THE PROTOCOL FOR WRITING!

    The first thing to be written must be the response line.  Then
    follow 0 or more header lines, then a blank line, and then the
    actual data (if any).  The meaning of the header lines depends on
    the command executed by the server; in most cases, when data is
    returned, there should be at least one header line of the form

    Content-type: <type>/<subtype>

    where <type> and <subtype> should be registered MIME types,
    e.g. "text/html" or "text/plain".

    """

    # The Python system version, truncated to its first component.
    sys_version = "Python/" + sys.version.split()[0]

    # The server software version.  You may want to override this.
    # The format is multiple whitespace-separated strings,
    # where each string is of the form name[/version].
    server_version = "BaseHTTP/" + __version__

    # The default request version.  This only affects responses up until
    # the point where the request line is parsed, so it mainly decides what
    # the client gets back when sending a malformed request line.
    # Most web servers default to HTTP 0.9, i.e. don't send a status line.
    default_request_version = "HTTP/0.9"

    def parse_request(self):
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an
        error is sent back.

        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        requestline = self.raw_requestline
        if requestline[-2:] == '\r\n':
            requestline = requestline[:-2]
        elif requestline[-1:] == '\n':
            requestline = requestline[:-1]
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            [command, path, version] = words
            if version[:5] != 'HTTP/':
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = 0
            if version_number >= (2, 0):
                self.send_error(505,
                          "Invalid HTTP Version (%s)" % base_version_number)
                return False
        elif len(words) == 2:
            [command, path] = words
            self.close_connection = 1
            if command != 'GET':
                self.send_error(400,
                                "Bad HTTP/0.9 request type (%r)" % command)
                return False
        elif not words:
            return False
        else:
            self.send_error(400, "Bad request syntax (%r)" % requestline)
            return False
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive
        self.headers = self.MessageClass(self.rfile, 0)

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0
        return True

    def handle_one_request(self):
        """Handle a single HTTP request.

        You normally don't need to override this method; see the class
        __doc__ string for information on how to handle specific HTTP
        commands such as GET and POST.

        """
        self.raw_requestline = self.rfile.readline()
        if not self.raw_requestline:
            self.close_connection = 1
            return
        if not self.parse_request(): # An error code has been sent, just exit
            return
        mname = 'do_' + self.command
        if not hasattr(self, mname):
            self.send_error(501, "Unsupported method (%r)" % self.command)
            return
        method = getattr(self, mname)
        method()

    def handle(self):
        """Handle multiple requests if necessary."""
        self.close_connection = 1

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def send_error(self, code, message=None):
        """Send and log an error reply.

        Arguments are the error code, and a detailed message.
        The detailed message defaults to the short entry matching the
        response code.

        This sends an error response (so it must be called before any
        output has been generated), logs the error, and finally sends
        a piece of HTML explaining the error to the user.

        """

        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        self.log_error("code %d, message %s", code, message)
        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': _quote_html(message), 'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(content)

    error_message_format = DEFAULT_ERROR_MESSAGE
    error_content_type = DEFAULT_ERROR_CONTENT_TYPE

    def send_response(self, code, message=None):
        """Send the response header and log the response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))
            # print (self.protocol_version, code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def send_header(self, keyword, value):
        """Send a MIME header."""
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s: %s\r\n" % (keyword, value))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = 1
            elif value.lower() == 'keep-alive':
                self.close_connection = 0

    def end_headers(self):
        """Send the blank line ending the MIME headers."""
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("\r\n")

    def log_request(self, code='-', size='-'):
        """Log an accepted request.

        This is called by send_response().

        """

        self.log_message('"%s" %s %s',
                         self.requestline, str(code), str(size))

    def log_error(self, format, *args):
        """Log an error.

        This is called when a request cannot be fulfilled.  By
        default it passes the message on to log_message().

        Arguments are the same as for log_message().

        XXX This should go to the separate error log.

        """

        self.log_message(format, *args)

    def log_message(self, format, *args):
        """Log an arbitrary message.

        This is used by all other logging functions.  Override
        it if you have specific logging wishes.

        The first argument, FORMAT, is a format string for the
        message to be logged.  If the format string contains
        any % escapes requiring parameters, they should be
        specified as subsequent arguments (it's just like
        printf!).

        The client host and current date/time are prefixed to
        every message.

        """
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))
                          
	#Self create folders & files deleted while program running.
	try:
		self_create_folders()
		self_create_files()
		self_create_user_photo()
	except:OSError

	
	
	
	name=self.address_string() # accessed user name
	#Day_special
	#Day_essentials
	#Community_process_accesspoint.
	b1=open('backbone/server/day_special.txt','r')
	b2=b1.readlines()
	b1.close()
	for i in b2:
		i1=i.split('_')
		i2=i1[-1].split('/')
	global special
	if int(i2[0])==int(time.strftime('%d')) and int(i2[1])==int(time.strftime('%m')):special=b2[-1]
	else:special='The program not found any special today'
	
	day_special=open('backbone/server/day_special.html','w')
	day_special.write('''<html><body><center><br><br><br><font color=white size=7 face="Penguin Attack">%s</font></center></body></html>'''%special)
	day_special.close()
	#auto select the photo
	def default_photo():
		f=os.listdir(path+'user/images/photoes/default_photo')
		try:
			if len(f)!=0:return 'default_photo/'+f[0]
			else:return 'current_time.gif'
		except:return 'current_time.gif'
        def photo(fn):
			f=os.listdir(path+'user/images/photoes')
			for i in f:
				if i.startswith(fn):return i
			return default_photo()
	
	
	space='&nbsp;'
	info=open('backbone/server/info.html','w')
	info.write('''<html><body bgcolor=black>
	<h3>%s<u><font color=yellow>Navigation Info</font></u></h3>
	<font color=white>
		%sHFS&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : &nbsp;&nbsp;It's for uploads & downloads files.<br>%sForums&nbsp;&nbsp;: &nbsp;&nbsp;To discuss the subject with online members.<br>%sHistory&nbsp;&nbsp;: &nbsp;&nbsp;To watch self history.<br>%sSpecial&nbsp;&nbsp; : &nbsp;&nbsp;To know the todays special.<br>%sQuotes&nbsp;&nbsp;&nbsp; : &nbsp;&nbsp;List of daily quotations.
	</font><br>
<h3>%s<u><font color=yellow>Site Info</font></u></h3><font color=white>%sWeb Language&nbsp;&nbsp;&nbsp;%s:%sBasic html & javascript <br>%sProgramming Language&nbsp;&nbsp;%s:%sPython<br>%sConstruction%s :%s14<sup>th</sup>Nov,2011  -  22<sup>nd</sup>Dec,2011</font><br><br>


<h3>%s<u><font color=yellow>Author Info</font></u></h3><font color=white>%sName %s:%sP.Susanth<br>%sClass %s :%sSS1<br>%sBatch%s&nbsp;:%s2009<br>%sInstitution &nbsp;&nbsp;&nbsp;&nbsp;:%sIIITN (rgukt)</font></body></html>'''%(space*11,space*11,space*11,space*11,space*11,space*11,space*11,space*11,space*19,space*4,space*11,space*5,space*4,space*11,space*25,space*4,space*11,space*11,space*11,space*4,space*11,space*11,space*4,space*11,space*11,space*4,space*11,space*4))
	info.close()
	# for online users time noting
	online_users=open('backbone/user/current_users.html','a')
	online_users.close()
	list_online_users=[]
	current_time=time.strftime("%T")#take the time as hours:minute:seconds
	time1=current_time.split(':')
	cuser=open('backbone/user/current_users.txt','a')
	cuser.write(name+'_'+str(int(time1[0])*3600+int(time1[1])*60+int(time1[2]))+'\n'),cuser.close()
	cud=open('backbone/user/current_users.txt','r')
	cunames=cud.readlines()
	cud.close()
	# online username reading
	reference_time=int(time1[0])*3600+int(time1[1])*60+int(time1[2])
	for i in cunames:
		data=i.split('_')
		user_name=data[0]
		accessed_time=int(data[1])
		if (reference_time-accessed_time)<=10:list_online_users.append(user_name)
	#upload & download info
        try:
		ud=open('backbone/user/histories/'+self.address_string()+'.html','r')
		u=ud.read()
		d=u.split('<br>')
		uc=0
		dc=0
		for i in d:
			u1=i.split('(')
			if u1[1].startswith('got'):dc+=1
			elif u1[1].startswith('sent'):uc+=1
        except:pass
#No. of visits counting program
        d = {}
        f= open("backbone/user/visits_counter.txt",'r')
        r=f.readlines()
        f.close()
        for i in r:
			n = i.split(':')
			d[n[0]] = n[1][:-1]
        def visit_count(name):
			if name in d:
				value=int(d[name])+1
				d[name]=value
			else:
				value=1
				d[name]=value
			for i in d:
				a=open('backbone/user/visits_counter.txt','a')
				a.write(i+':'),a.write(str(d[i])),a.write('\n')
				a.close()
			f=open('backbone/user/visits_counter.txt','w')
			for i in d:
				f.write(i+':'),f.write(str(d[i])),f.write('\n')
			f.close()
        visit_count(name)
        
        
        
	 #list of the online users
	current_users=[]
	for j in list_online_users:
		if j not in current_users:current_users.append(j)
	online_users=open('backbone/user/current_users.html','w')
	online_users.write('''<html><head><meta http-equiv='Refresh' content="2;url=current_users.html"/></head><body><font color=purple><center><font size=5 color=brown face=Arial><b>( %s )</b></font></center>online members</font><br>'''%len(current_users))
	for l in current_users[::-1]:
		online_users.write("&nbsp;<img src='images/photoes/%s' width='25px' height='30px' border='1px'>&nbsp;<font color=white face=KacstTitleL><sup><b>%s</b></sup></font><br>"%(photo(l),l))
	online_users.write('</body></html>')
	online_users.close()

	photoes=os.listdir('backbone/user/images/photoes') # list all users photoes
	
	#history writing
	history=open('backbone/user/histories/'+name+'.html','a')# create empty history file

	# note the history file treatment history

	def history(time,file_name,treat):
		history=open('backbone/user/histories/'+name+'.html','a')
		history.write("<li>&nbsp;&nbsp;&nbsp;<font color=purple>%s</font>--<font color=green>(%s)</font>--[%s]</li><br>" %(file_name,treat,time))
		history.close()

	# new comments writing 
	comment_page=open("backbone/user/forums/comments.html","a")
	def comment(msg,usr,time):
		new_comment=open("backbone/user/forums/comments.txt","a")
		new_comment.write("""%s_._%s_._%s"""%(msg,usr,time)),new_comment.write("\n"),new_comment.close()
		comment_html=open("backbone/user/forums/comments.html","w") # new comments updates html page
		comment_html.write("""<html><head><meta http-equiv='Refresh' content="7;url=comments.html"/></head><body bgcolor=#F3F3FF>""")
		a=open("backbone/user/forums/comments.txt","r")
		b=a.readlines()
		a.close()
		rlist=b[::-1]
		for i in range(len(rlist)):
			c=len(rlist)-i
			comm=rlist[i].split('_._')
			comment_html.write('''&nbsp;<img src='%s' width='25px' height='30px' border='1px'><sup>&nbsp;<font size=2 color=grey>(<i>%s %s</i>)</font></sup><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size=4 color=purple face="Andika Basic">%s<font><br>\n'''%(url+'/backbone/user/images/photoes/'+photo(comm[1]),comm[1],comm[2],comm[0]))
		comment_html.close()
	# convert the input data into suitable user understandable form
	def conv(msg):
		list1=['%20','+','++','+++','++++','+++++','++++++','+++++++','++++++++','+++++++++','++++++++++','%0D%0A','0D 0A','%21','%40','%23','%24','%25','%5E','%26','%28','%29','%3D','%2B','%7B','%7D','%5B','%5D','%5C','%7C','%3B','%3A','%27','%22','%2C','%2F','%3F','%3C','%3E','%60','%7E']
		list2=[' ',' ','  ','   ','    ','     ','      ','       ','        ','         ','          ','<br>','<br>','!','@','#','$','%','^','&','(',')','=','+','{','}','[',']',"\\",'|',';',':','\'','"',',','/','?','<','>','`','~']
		if len(msg)!=0:
			for i in range(len(list1)):
				if list1[i] in msg:
					msg=msg.replace(list1[i],list2[i])
			return msg

        #Create history of each individual and note daily history of them with date,time and got or sent data or file
        a=format%args

        
 
        if "GET /" in a:
		cfu=open('backbone/user/forums/current_forum_users.txt','a')
		fuser=open('backbone/user/forums/current_forum_users.html','a')
		fuser.write('''<html><head><meta http-equiv='Refresh' content="2;url=current_forum_users.html"/></head><body>'''),fuser.close()
		b=a[6:-16] #comments text data destiny
		Fnam=b.split('/')# download file data destiny
		if ('_._' in Fnam[-1]) and (Fnam[-1] not in photoes):
			d_msg=Fnam[-1].split('_._')[-1]
			history(self.log_date_time_string(),conv(d_msg),'got')# Downloaded history noted
        	if "textarea.html?uptext" in a: #"backbone/user/forums/textarea.html?uptext"
        		data=a.split('=')
			comment_data=data[1][:-16]	
        		comment(conv(comment_data),name,time.strftime("%d/%m/%y %H:%M:%S"))
		#'/backbone/user/forums/comments.html'
		if '/comments.html' in a: #for note the current forum users names
			# for online users time noting
			list_online_forum_users=[]		
			current_timef=time.strftime("%T")#take the time as hours:minute:seconds
			time2=current_timef.split(':')
		# online username reading
			cfu.write(name+'_'+str(int(time2[0])*3600+int(time2[1])*60+int(time2[2]))+'\n')
			cfu.close()
			fu=open('backbone/user/forums/current_forum_users.txt','r')
			funames=fu.readlines()
			fu.close()
			reference_timef=int(time2[0])*3600+int(time2[1])*60+int(time2[2])
			for i in funames:
				dataf=i.split('_')
				user_name=dataf[0]
				accessed_timef=int(dataf[1])
				if (reference_timef-accessed_timef)<=5:list_online_forum_users.append(user_name)
			for j in list_online_forum_users:
				if j not in current_forum_users:current_forum_users.append(j)
			
        	        #Delete the photo by user command.
		def photo_delete(n,da):
			fs=os.listdir('backbone/user/images/photoes')
			if len(da)!=0 and da=='del':
				try:
					for i in fs:
						if i.startswith(n):
							return fs+'/'+i
				except:OSError
        	if "upload_photo.html?uptext" in a:
        		data=a.split('=')
			comment_data=data[1][:-16]	
        		print photo_delete(name,conv(comment_data))	
	# if the 'Recieved' in data msg		
        elif "Received:" in a:
        	b=a[9:]
        	global u_msg
		u_msg=b.split('_._')[-1]
		history(self.log_date_time_string(),conv(u_msg),'sent')# Uploaded history noted
        if 'POST /backbone/user/upload_photo.html' in a: # Rename the uploaded photo instantly upoading
			st=u_msg.split('.')[-1]
			for i in photoes:
				if i.startswith(self.address_string()):
					sn=i.split('.')
					os.rename("backbone/user/images/photoes/"+i,"backbone/user/images/photoes/"+self.address_string()+'.'+st)
				
      	        
        textarea=open("backbone/user/forums/textarea.html","w")
        textarea.write(''' <html><body><form method="send" enctype="multipart/form-data" action="">
 <textarea style="width:700px;height:70px;background-color:#F3F3FF" name="uptext" type="text"></textarea><br>
 <input value="Submit" onclick="swap()" type="submit">
  </form></body></html>'''),textarea.close()
        # main comment page creating & write the required data into it.
    
        forums=open("backbone/user/forums/forums.html","w")
        forums.write(''' <html><body>
&nbsp;&nbsp;<font color=green>write comment:-</font><font color=black>&nbsp;&nbsp;All Languages & Scripts Supports(Ex:Hindi & HTML)</font><br><iframe  src="textarea.html" width="940px" height="120px" frameborder='0' scrolling='no'></iframe><br>
<div style='position:absolute;top:130px;left:10px'>
<iframe  src="comments.html" width="1000px" height="338px" frameborder='0' scrolling='yes'></iframe></div><br>
</body></html>''')
	forums.close()
	


	
	# total visits counting
	v=open('backbone/user/visits_counter.txt','r')
	v1=v.readlines()
	total_visits=0
	for i in v1:
		v2=i.split(':')
		total_visits+=int(v2[1])

	#modify
	# the site main (home) page creating and required data

	# for single daily quote
	quote=open('backbone/server/quotes.txt','r')
	q1=quote.readlines()
	quotation=q1[-1]
	quote.close()
	# for (quotes.html) all quotations
	quotes=open('backbone/server/quotes.html','w')
	quotes.write('''<html><body bgcolor=black>''')
	c=0
	for i in q1[::-1]:
		c=c+1
		i1=i.split('_')
		quotes.write('&nbsp;&nbsp;&nbsp;<font color=grey><i>%d. %s<i></font> &nbsp;&nbsp;&nbsp;<font color=pink>%s</font></font></br>'%(c,i1[0],i1[1]))
	quotes.write('</body></html>')
	quotes.close()
	
	# for site background !!
	try:
		ldb=os.listdir(os.getcwd()+"/backbone/user/images/background")
		if len(ldb)!=0:
			background="background=backbone/user/images/background/"+ldb[0]
		else:
			background="bgcolor=skyblue"
	except:background="bgcolor=skyblue"
	
	# Homepage Design below
	index=open("index.html","w")
	index.write('''<html>
<head><title>@ Mini world @</title></head>
<body '''+background+'''>

    
<script type="text/javascript">
var currentTime = new Date()
var hours = currentTime.getHours()
var minutes = currentTime.getMinutes()
if (minutes < 10){
minutes = "0" + minutes
}
if(hours > 11){if (16<=hours){alert('Good Evening " '''+name+''' "')}else{alert('Good Afternoon " '''+name+''' "')}} else{alert('Good Morning " '''+name+'''" ')}
</script>




<br>
<div style="position:absolute;top:10px;left:160px;background:grey;width:1020px;height:35;border:1px solid black;">
<center>
<a style='text-decoration:none;'  href="backbone/user/forums/forums.html" title="Go to Forums" target="magazine"><button style='color:green;height:30px;width:80px'>Forums</button></a>&nbsp;&nbsp;

<a style='text-decoration:none;'  href="backbone/sync/universal" title="Go to public Sharing Files" target="magazine"><button style='color:green;height:30px;width:130px'>Subjects HFS</button></a>&nbsp;&nbsp;	

<a style='text-decoration:none;'  href="backbone/sync/personal" title="Go to public Sharing Files" target="magazine"><button style='color:green;height:30px;width:130px'>General HFS</button></a>&nbsp;&nbsp;

<a style='text-decoration:none;'  href="backbone/user/histories/'''+name+'''.html" title="Go to Watch Your History" target="magazine"><button style='color:green;height:30px;width:80px'>History</button></a>&nbsp;

<a style='text-decoration:none;'  href="backbone/server/info.html" title="Go to know the Information" target="magazine"><button style='color:green;height:30px;width:80px'>Info</button></a>&nbsp;

<a style='text-decoration:none;'  href="backbone/server/day_special.html" title="Go to know the today's special" target="magazine"><button style='color:green;height:30px;width:130px'>Day Special</button></a>&nbsp;

<a style='text-decoration:none;'  href="backbone/server/quotes.html" title="Go to the list of daily quotations" target="magazine"><button style='color:green;height:30px;width:80px'>Quotes</button></a>&nbsp;

</center>
</div>

<div style="position:absolute;top:50px;left:150px">
<table>
<td>
<iframe name="magazine" id="magazine" src="backbone/server/welcome.html" width="1030" height="490px" marginwidth="0" marginheight="0" hspace="0" vspace="0" allowtransparency="allowtransparency" frameborder="0" scrolling="yes"></iframe></td>
</td></table>
</div>

<div style='position:absolute;left:150px;top:545px;font-family:FreeSerif;font-size:20;color:blue;background:skyblue;width:1030px;height:25;border:1px solid black;'><font color=black size=4>Quote : </font>%s&nbsp;&nbsp;&nbsp;</div>

<div style='position:absolute;top:10px;left:1180px;'><iframe src="backbone/user/current_users.html" width="150" height="530px" marginwidth="0" marginheight="0" hspace="0" vspace="0" allowtransparency="allowtransparency" frameborder="1" scrolling="yes"></iframe></div>

<div style='position:absolute;top:10px;left:5px;'><iframe src="backbone/user/profile.html" width="150" height="530px" marginwidth="0" marginheight="0" hspace="0" vspace="0" allowtransparency="allowtransparency" frameborder="1" scrolling="yes"></iframe></div>
<div style="position:absolute;top:545px;left:6px;color:white;background:black;width:140px;height:25;border:1px solid white;"><center>Visits : %d</center></div>
<div style="position:absolute;top:545px;right:20px;color:white;background:black;width:150px;height:25;border:1px solid white;"><center>&copy;P.Susanth</center></div>
</body>
</html>


'''%(quotation.split('_')[0],total_visits))
        index.close()
      	
        
	#welcome page creating
	

	#photo info
	welcome=open('backbone/server/welcome.html','w')
	welcome.write('''<html><body><h4><br><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Welcome to main page</h4><center><br><br><font color=white> Let's dive into the site....................!</font></center></body></html>''')
	welcome.close()
	#user main page creating and presenting the required data
	def photo_availablity(fn):
		f=os.listdir(path+'user/images/photoes')
		for i in f:
			if i.startswith(fn):return 'change photo'
		return 'upload photo'
	#client profile info display
	date=self.log_date_time_string()
        profile=open('backbone/user/profile.html','w')
        profile.write("""<html><br><center><img src='images/photoes/%s' width='125px' height='140px' border='1px'><br><font size=2 color=white>%s&nbsp;&nbsp;<a style='text-decoration:none' target='_blank' href="upload_photo.html">Go</a></font></center><br><font size=2>&nbsp;<font color=blue><u><b>profile details</b></u> :</font><br>&nbsp;Name  : %s<br>&nbsp;Uploads : %d<br>&nbsp;Downloads : %d<br>&nbsp;Visits : %d</font><br><br>&nbsp;<font color=brown size=2>Date : %s</font>

"""%(photo(name),photo_availablity(name),name,uc,dc,d[name],date.split()[0]))
        profile.close()

        upload_photo=open("backbone/user/upload_photo.html","w")
        upload_photo.write("""<html><head><title>upload photo/image</title></head><body bgcolor=skyblue><center> <br><br><br><br><br><br>upload the image<br><br><div  id="wrap">
  <div id="wrapform">
    <div id="form">
      <form style='color:green' method="post" enctype="multipart/form-data" action="">
        <input name="upfile" type="file">
        <input style="color:green"value="Upload" onclick="swap()" type="submit">
      </form>
    </div>
  </div>
</div>
<br>* The uploaded image/photo must treated as your account image.<br><br>
<br><br><a style='text-decoration:none;' href='%s' ><button style="color=green font-size=8" >Back to Home</button></a><br><br></center><body></html>"""%url)
        upload_photo.close()
        
        
        

							    	  		
									    	  		
   
	
	

    def version_string(self):
        """Return the server software version string."""
        return self.server_version + ' ' + self.sys_version

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
                day, self.monthname[month], year, hh, mm, ss)
        return s

    weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def address_string(self):
        """Return the client address formatted for logging.

        This version looks up the full hostname using gethostbyaddr(),
        and tries to find a name that contains at least one dot.

        """
	
        host, port = self.client_address[:2]
        return getfqdn(host)



    # Essentially static class variables

    # The version of the HTTP protocol we support.
    # Set this to HTTP/1.1 to enable automatic keepalive
    protocol_version = "HTTP/1.0"

    # The Message-like class used to parse headers
    MessageClass = mimetools.Message

    # Table mapping response codes to messages; entries have the
    # form {code: (shortmessage, longmessage)}.
    # See RFC 2616.
    responses = {
        100: ('Continue', 'Request received, please continue'),
        101: ('Switching Protocols',
              'Switching to new protocol; obey Upgrade header'),

        200: ('OK', 'Request fulfilled, document follows'),
        201: ('Created', 'Document created, URL follows'),
        202: ('Accepted',
              'Request accepted, processing continues off-line'),
        203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
        204: ('No Content', 'Request fulfilled, nothing follows'),
        205: ('Reset Content', 'Clear input form for further input.'),
        206: ('Partial Content', 'Partial content follows.'),

        300: ('Multiple Choices',
              'Object has several resources -- see URI list'),
        301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
        302: ('Found', 'Object moved temporarily -- see URI list'),
        303: ('See Other', 'Object moved -- see Method and URL list'),
        304: ('Not Modified',
              'Document has not changed since given time'),
        305: ('Use Proxy',
              'You must use proxy specified in Location to access this '
              'resource.'),
        307: ('Temporary Redirect',
              'Object moved temporarily -- see URI list'),

        400: ('Bad Request',
              'Bad request syntax or unsupported method'),
        401: ('Unauthorized',
              'No permission -- see authorization schemes'),
        402: ('Payment Required',
              'No payment -- see charging schemes'),
        403: ('Forbidden',
              'Request forbidden -- authorization will not help'),
        404: ('Not Found', 'Nothing matches the given URI'),
        405: ('Method Not Allowed',
              'Specified method is invalid for this server.'),
        406: ('Not Acceptable', 'URI not available in preferred format.'),
        407: ('Proxy Authentication Required', 'You must authenticate with '
              'this proxy before proceeding.'),
        408: ('Request Timeout', 'Request timed out; try again later.'),
        409: ('Conflict', 'Request conflict.'),
        410: ('Gone',
              'URI no longer exists and has been permanently removed.'),
        411: ('Length Required', 'Client must specify Content-Length.'),
        412: ('Precondition Failed', 'Precondition in headers is false.'),
        413: ('Request Entity Too Large', 'Entity is too large.'),
        414: ('Request-URI Too Long', 'URI is too long.'),
        415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
        416: ('Requested Range Not Satisfiable',
              'Cannot satisfy request range.'),
        417: ('Expectation Failed',
              'Expect condition could not be satisfied.'),

        500: ('Internal Server Error', 'Server got itself in trouble'),
        501: ('Not Implemented',
              'Server does not support this operation'),
        502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
        503: ('Service Unavailable',
              'The server cannot process the request due to a high load'),
        504: ('Gateway Timeout',
              'The gateway server did not receive a timely response'),
        505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
        }

def initializing_test(HandlerClass = BaseHTTPRequestHandler,     #This is the first test of the program
         ServerClass = HTTPServer, protocol="HTTP/1.0"):
    """Test the HTTP request handler class.

    This runs an HTTP server on port 8000 (or the first command line
    argument).

    """

    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = PORT
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    # Running Service Message Declaration area
    print "Running The Local Server Successfully..!\nServer Address - ",IP+':'+str(PORT),'\nPress Ctrl+C to terminate the program.'
    global url
    url='http://'+IP+':'+str(PORT)
    try:
    	webbrowser.open(url)
    except:pass
    httpd.serve_forever()

#------------@@@ BaseHTTPServer Code ended  @@@----------------------------------#


#-------------@@@ SimpleHTTPServer Code Started @@@ ---------------------------#
"""Simple HTTP Server.

This module builds on BaseHTTPServer by implementing the standard GET
and HEAD requests in a fairly straightforward manner.

"""

__version__ = "0.6"

__all__ = ["SimpleHTTPRequestHandler"]

__version__ = "0.6"

__all__ = ["SimpleHTTPRequestHandler"]

import os
import getpass
import posixpath
import urllib
import cgi
import shutil
import mimetypes
import tempfile
import copy
import posixpath
import macpath
import ntpath
import time

#create user-preferred folders
def request_path(uri):
	if uri[-2] == 'personal':
		return os.curdir + '/backbone/sync/personal'
	elif uri[-2] == 'universal':
		return os.curdir + '/backbone/sync/universal'
	elif uri[-2] == 'Susanth_._Physics':
		return os.curdir + '/backbone/sync/universal/Susanth_._Physics'
	elif uri[-2] == 'Susanth_._Mathematics':
		return os.curdir + '/backbone/sync/universal/Susanth_._Mathematics'
	elif uri[-2] == 'Susanth_._English':
		return os.curdir + '/backbone/sync/universal/Susanth_._English'
	elif uri[-2] == 'Susanth_._MP':
		return os.curdir + '/backbone/sync/universal/Susanth_._MP'
	elif uri[-2] == 'Susanth_._PDS':
		return os.curdir + '/backbone/sync/universal/Susanth_._PDS'
	else:
		return  os.curdir + '/backbone/user/images/photoes'

directory = os.curdir
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


class DroopyFieldStorage(cgi.FieldStorage):

    def make_file(self, binary=None):
	try:
		request = self.raw_requestline
		request1 = request.split()
		request2 = request1[1][1:].split('/')
		directory=request_path(request2)
	except:
		directory = os.curdir
        fd, name = tempfile.mkstemp(dir=directory)
        self.tmpfile = os.fdopen(fd, 'w+b')
        self.tmpfilename = name
        return self.tmpfile

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    form_field = 'upfile'

    """Simple HTTP request handler with GET and HEAD commands.

    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method.

    The GET and HEAD requests are identical except that the HEAD
    request omits the actual contents of the file.

    """

    server_version = "SimpleHTTP/" + __version__

    def do_GET(self):
        """Serve a GET request."""
	unreveal = ['images','sync','histories','forums','user','backbone','server']
	# unreveal is what you dont want to let others take. For example you .py file.......
	request = self.raw_requestline
	request1 = request.split()
	request2 = request1[1].split('/')
	safe = []
	for i in request2:
		if i != '':
			safe.append(i)
	if len(safe) == 0:
		safe.append('hai')
	if safe[-1] not in unreveal:
	       	f = self.send_head()
	       	if f:
	       	    self.copyfile(f, self.wfile)
	       	    f.close()
	else:
		self.send_error(404, "File not found")
    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def send_head(self):
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f


    def do_POST(self):
        # Do some browsers /really/ use multipart ? maybe Opera ?
        try:
            self.log_message("Started file transfer")   
            # -- Set up environment for cgi.FieldStorage
            env = {}
            env['REQUEST_METHOD'] = self.command
            if self.headers.typeheader is None:
                env['CONTENT_TYPE'] = self.headers.type
            else:
                env['CONTENT_TYPE'] = self.headers.typeheader

            # -- Save file (numbered to avoid overwriting, ex: foo-3.png)
            form = DroopyFieldStorage(fp = self.rfile, environ = env);
            fileitem = form[self.form_field]
	# add the host_name to file
            filename = self.basename(fileitem.filename).decode('utf-8')
            if filename == "":
                raise Exception("Empty filename")
            filename = self.address_string()+'_._'+self.basename(fileitem.filename).decode('utf-8')
	    try:
	    	request = self.raw_requestline
	    	request1 = request.split()
	    	request2 = request1[1][1:].split('/')
	    	directory = request_path(request2)
	    except:
	    	directory = os.curdir
            localpath = os.path.join(directory, filename).encode('utf-8')
            root, ext = os.path.splitext(localpath)
            i = 1
            # race condition, but hey...
            while (os.path.exists(localpath)): 
                localpath = "%s-%d%s" % (root, i, ext)
                i = i+1
            if hasattr(fileitem, 'tmpfile'):
                # DroopyFieldStorage.make_file() has been called
                fileitem.tmpfile.close()
                shutil.move(fileitem.tmpfilename, localpath)
            else:
                # no temporary file, self.file is a StringIO()
                # see cgi.FieldStorage.read_lines()
                fout = file(localpath, 'wb')
                shutil.copyfileobj(fileitem.file, fout)
                fout.close()
            self.log_message("Received: %s", os.path.basename(localpath))

            # -- Reply
	    FFilename=os.path.basename(localpath)
	    F=FFilename.split('_._')
            self.do_GET()
	    self.wfile.write('''<script language = "JavaScript">alert("\t\tUploaded '%s' successfully ")</script>''' %F[-1])

        except Exception, e:
            self.log_message(repr(e))
            self.do_GET()
	    self.wfile.write('''<script language = "JavaScript">alert(" \t\tUploaded Nothing ")</script>''')
    def basename(self, path):

        for mod in posixpath, macpath, ntpath:
            path = mod.basename(path)
        return path



    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        f = StringIO()
        displaypath = cgi.escape(urllib.unquote(self.path))
        f.write('<!DOCTYPE html universal "-//W3C//DTD HTML 3.2 Final//EN">')
        request = self.raw_requestline
        request1 = request.split()
        nrl = request1[1][1:].split('/')
        # legth of the display name cutting::!
        def filename_cut(fi):
        	if len(fi)<40:return fi
        	else:return fi[0:40] 
        #The below inputs for each files
        line=5
        side=10
        file_count=0
        for name in list[::-1]:
        #-------------------------------------------------------------------------------------------------------
	    undisplay = ['run.py']
	    #-----------------------------------------------------------------------------------------------------
		
	    file_count=file_count+1
	    line=line+28
	    split_fullname=name.split('_._')
	    uploader=split_fullname[0]
	    name=split_fullname[-1]
	    if name not in undisplay:
	            fullname = os.path.join(path, name)
	            displayname = name
	            linkname= uploader+'_._'+name
	            # Append / for directories or @ for symbolic links
	            if os.path.isdir(fullname):
	                displayname = name + "/"
	                linkname = name + "/"
	            if os.path.islink(fullname):
	                displayname = name + "@"
   # Note: a link to a directory displays with @ and links with /
	            f.write('''<div style='position:absolute;top:%dpx;left:10px;border:1px solid white;width:60px;height:25px'><center><font color=white>%d</font></div><a style="text-decoration:none;color:blue;font-size:17;font-family:FreeSerif" href="%s"><div style='position:absolute;left:73px;top:%dpx;border:1px solid white;height:25px;width:490px'><font color=blue><center>%s</font></a></div><div style='position:absolute;left:566px;top:%dpx;border:1px solid white;height:25px;width:150px'><center><font color=white>%s</font></div></div>'''% (line,file_count,urllib.quote(linkname),line,filename_cut(cgi.escape(displayname)),line,uploader))
        f.write("<div style='position:absolute;left:10px;top:5px;border:1px solid white;height:25px;width:60px'><center>S.No</center></div><div style='position:absolute;left:73px;top:5px;border:1px solid white;height:25px;width:490px'><center>Filename</center></div><div style='position:absolute;left:566px;top:5px;border:1px solid white;height:25px;width:150px'><center>Uploaded by</center></div></div>")
	f.write('''<br><div style="position:absolute;right:280px;top:5px;width:1px;height:100px">
    <div id="form" >
      <form style='color:green;' method="post" enctype="multipart/form-data" action="">
        <input name="upfile"  type="file">
        <input style="color:green"value="Upload" onclick="swap()" type="submit">
      </form>
  </div>
</div>''')
        f.write("<br></body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = os.getcwd()
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.

        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).

        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.

        """
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        """Guess the type of a file.

        Argument is a PATH (a filename).

        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.

        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.

        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })


pwd='rgukt123'
def test(HandlerClass = SimpleHTTPRequestHandler,
         ServerClass =HTTPServer):
    initializing_test(HandlerClass, ServerClass)
if __name__ == '__main__':
    try:
	    if getpass.getpass()==pwd:
		print 'Authorized, Server will be run now......!'
		self_create_folders()
		self_create_user_photo()
		self_create_files()
		self_setup_ip_port()
		test()
	    else:
		print 'Sorry, Authorization not allow......!'

    except KeyboardInterrupt:
	    print 'Shutting down...........'
#Delete negation & unstorable files which is created while program running.
    f_list=['index.html','backbone/user/forums/forums.html','backbone/user/profile.html','backbone/user/upload_photo.html','backbone/user/forums/textarea.html','backbone/user/current_users.txt','backbone/user/current_users.html','backbone/homepage.html','backbone/user/images/photoes/current_time.gif','backbone/server/info.html','backbone/server/help.html','backbone/server/updates.html','backbone/server/welcome.html','backbone/server/day_special.html']
    for i in f_list:
    	try:
			os.remove(i)
    	except:OSError

