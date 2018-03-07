#encoding: utf8
import traceback
import sys
import re
import time
from Toolbox.ColorTools import *
from Toolbox.EnvirTools import *
from Toolbox.FileTools import *
from Toolbox.IfaceTools import *

CheckEnvir()

from scapy.all import *
from scapy.utils import PcapWriter
import scapy_http.http as http


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
        self.filtermode = '( tcp[13:1]==24 )' #'tcp[13:1]==24' -> only sniff tcp
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

    def Init(self):
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
        print '  [-]Filter:', putColor(self.filtermode, 'green')
        
        try:
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
                ErrorDog(self.Exit)         
        
    def Collector(self, pkt):
        try: 
            if self.savingPcap: 
                self.pktdump.write(pkt)
            
            self.AllPackages += 1
            if pkt.haslayer(http.HTTPRequest): 
                self.FoundRequest(pkt)

                #Use plug-in?
                #if '10.255.44.33' in [pkt.src, pkt.dst]: self.Plugin(pkt, 'pwd')	    

            print '\r  [%s]' %self.sign[self.AllPackages%4] + putColor(
                'AllPackages %d' %self.AllPackages, 'white'), '  ' + putColor(
                    'RequestPackages %d' %self.RequestPackages, 'blue'), '  ' + putColor(
                        'CookiePackages %d' %self.CookiePackages,'cyan'), '  ' + putColor(
                            'PostPackages %d' %self.PostPackages, 'yellow'), '  ',

            ClearLine()

        except Exception, e:
            if 'ascii' not in str(e):
                ErrorDog(self.Exit)               


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
                    ErrorDog(self.Exit)         


    def ExtractInfo(self, pkt, method):
        if method == 'Cookie': colormethod = 'green'
        else: colormethod = 'cyan'        
        info = ['[%s]Found %s' %(putColor(time.strftime("%H:%M:%S", time.localtime()), 'white'), putColor(method, colormethod))]
        info.append('[+]From %s to %s' %(putColor(pkt.src, 'blue'), pkt.dst))
        info.append('  [-]Method: %s' %pkt.Method)
        try:
            ua = re.findall('(User-Agent: .+)', str(pkt.payload))
        except: ua = ''

        if ua: info.append('  [-]%s' %ua[0])
        else: info.append('  [-]User-Agent:')
        info.append('  [-]Host: %s' %putColor(pkt.Host, 'green'))
        info.append('  [-]Url: %s' %(pkt.Host + pkt.Path))
        if method == 'Post': info.append('  [-]PostDatas: %s' %putColor(pkt.load, 'yellow'))

        if pkt.Cookie == None: pkt.Cookie = '' 
        info.append('  [-]Cookie: %s' %putColor(pkt.Cookie, 'yellow'))     

        if self.savingPkt: 
            SavePkts(Eraser('\n'.join(info)+'\n'+'-'*60 + '\n'), method, self.sfilename, pkt.src, pkt.Host)

        if self.outputmode:
            print '\r' + ' '*200 + '\n' + '\n'.join(info)


    def Plugin(self, pkt, plugname):
        #Your plug-in in ./Plugin
        #Such as: mode name is PPPPPPPrint
        #Then you should use: 
        #import Plugin.PPPPPPPrint
        #
        if plugname == 'fhost':
            flist = []

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


iHost = []

Sniffer(savingPkt = 1, savingPcap = 1, iHost = iHost)
#Sniffer(filename='test.pcap', savingPkt = 0, iHost = iHost)