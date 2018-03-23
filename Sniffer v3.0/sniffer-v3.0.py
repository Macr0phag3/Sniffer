#encoding: utf8
import traceback
import sys
import re
import time
import commands
from Toolbox.EnvirTools import *

if not CheckEnvir(): sys.exit(1)

from Toolbox.ColorTools import *
from Toolbox.FileTools import *
from Toolbox.IfaceTools import *
from scapy.all import *
from scapy.utils import PcapWriter
import scapy_http.http as http
import argparse

class Sniffer:
    AllPackages = 0
    RequestPackages = 0
    CookiePackages = 0
    PostPackages = 0
    pic = '''
[1m[36m     _______..__   __. [0m[1m[31m __ [0m [1m[36m _______  _______  _______ .______      [0m
[1m[36m    /       ||  \ |  | [0m[1m[31m|  |[0m [1m[36m|   ____||   ____||   ____||   _  \     [0m
[1m[36m   |   (----`|   \|  | [0m[1m[31m|  |[0m [1m[36m|  |__   |  |__   |  |__   |  |_)  |    [0m
[1m[36m    \   \    |  . `  | [0m[1m[31m|  |[0m [1m[36m|   __|  |   __|  |   __|  |      /     [0m
[1m[36m.----)   |   |  |\   | [0m[1m[31m|  |[0m [1m[36m|  |     |  |     |  |____ |  |\  \----.[0m
[1m[36m|_______/    |__| \__| [0m[1m[31m|__|[0m [1m[36m|__|     |__|     |_______|| _| `._____|[0m [1m[33mv3.0[0m
'''
    print pic

    def __init__(self):       
        parser = argparse.ArgumentParser(description='Version: 3.0; Running in Py2.x')
        parser.add_argument("-i", default='', help="the interface you want to use")
        parser.add_argument("-mi", default='mon0', help="name of the interface in monitor mode")
        parser.add_argument("-f", default='', help="local pcap filename(in the offline mode)")
        parser.add_argument("-o", default='1', help="show msg in the terminal? 0: No, 1: Yes")
        parser.add_argument("-sPkt", default='1', help="save Pkts during snifffing? 0: No, 1: Yes")
        parser.add_argument("-sPcap", default='0', help="save Pcap during snifffing? 0: No, 1: Yes")
        parser.add_argument("-fm", default='', help="filter syntax used in scapy")
        parser.add_argument("-iHF", default='iHost.txt', help="highlight these hosts when stop the sniffer(in the iHost.txt")
        parser.add_argument("-fHF", default='fHost.txt', help="filter these hosts when show msg in terminal(in the fHost.txt")
        args = parser.parse_args() 
        
        self.iface = args.i #old interface 
        self.newiface = args.mi #a new interface in monitor mode
        self.sign = ['—','\\' ,'|' ,'/'] #stupid thing :)
        self.filename = args.f #local pcap filename
        self.sfilename = str(int(time.time()))
        self.outputmode = args.o #0->don't output, 1->output
        self.savingPkt = args.sPkt #0->don't save, 1->save
        self.savingPcap = args.sPcap
        self.filtermode = '( tcp[13:1]==24 )'#'tcp[13:1]==24' -> only sniff tcp
        self.SrcIP = []
        self.fHF = args.fHF
        
        if args.fm: self.filtermode += ' and ( %s )' %args.fm #

        if self.savingPkt == '1': InitPktsFile(self.sfilename)
        if self.savingPcap == '1': self.pktdump = PcapWriter("./Pcaps/%s.pcap" %(self.sfilename), append=True, sync=True)
        
        try:
            with open(args.iHF, 'r') as fp:
                self.iHost = re.findall('(\S+)', fp.read())
        except:
            ErrorDog(self.Exit)
            
        if self.iface == '' and self.filename: 
            print putColor('[!]Offline Mode!', 'green')
            print '  [-]Filter:', putColor(self.filtermode, 'green')
            print '  [-]',
            ClearLine() 
            
            try:
                pkt = sniff(offline = './Pcaps/' + self.filename,    
                        prn = self.Collector,    
                        filter = self.filtermode,   
                        store = 0)#DO NOT USING store = 1!!!              
                                  #Or you'll see your memory BOOM
                print 
            except:
                ErrorDog(self.Exit)
                
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
            if self.savingPcap == '1': 
                self.pktdump.write(pkt)
            
            self.AllPackages += 1
            if pkt.haslayer(http.HTTPRequest): 
                self.FoundRequest(pkt)
                
            print '\r  [%s]' %self.sign[self.AllPackages%4] + putColor(
                'AllPackages %d' %self.AllPackages, 'white'), '  ' + putColor(
                    'RequestPackages %d' %self.RequestPackages, 'blue'), '  ' + putColor(
                        'CookiePackages %d' %self.CookiePackages,'cyan'), '  ' + putColor(
                            'PostPackages %d' %self.PostPackages, 'yellow'), '  ' + putColor(
                                'HostNum %d' %len(self.SrcIP), 'white'), '  ',

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
        if pkt.src not in self.SrcIP: self.SrcIP.append(pkt.src)
        info.append('  [-]Method: %s' %pkt.Method)
        try:
            ua = re.findall('(User-Agent: .+)', str(pkt.payload))
            info.append('  [-]%s' %ua[0])
        except: 
            info.append('  [-]User-Agent:')
            
        if not pkt.Host: pkt.Host = 'Unknow'
        info.append('  [-]Host: %s' %putColor(pkt.Host, 'green'))
        
        info.append('  [-]Url: %s' %(pkt.Host + pkt.Path))
        if method == 'Post': info.append('  [-]PostDatas: %s' %putColor(pkt.load, 'yellow'))

        if pkt.Cookie == None: pkt.Cookie = '' 
        info.append('  [-]Cookie: %s' %putColor(pkt.Cookie, 'yellow'))     

        if self.savingPkt == '1': 
            SavePkts(Eraser('\n'.join(info)+'\n'+'-'*60 + '\n'), method, self.sfilename, pkt.src, pkt.Host)

        if self.outputmode == '1':
            print '\r' + ' '*200 + '\n' + '\n'.join(info)

        #self.Plugin(None, 'QzoneCookie', args=[pkt.src, pkt.Cookie])
        
    def Plugin(self, pkt, plugname, args=[]):
        #Your plug-in in ./Plugin
        #Such as: mode name is PPPPPPPrint
        #Then you should use: 
        #import Plugin.PPPPPPPrint
        
        #if plugname == 'QzoneCookie':
        #    import Plugin.QzoneCookie as Qzone
        #    Qzone.QzoneCookieUsage(args)

        if plugname == 'fhost':
            try:
                with open(self.fHF, 'r') as fp:
                    flist = re.findall('(\S+)', fp.read())
            except: 
                ErrorDog(self.Exit)
            
            if pkt.Host:
                if flist and re.search('(%s)' %')|('.join(flist), pkt.Host): 
                    return False
            
            return True


    def Exit(self):
        print '\n[!]Shutting Down...'
        if self.filename == '': 
            print '  [-]Down %s...' %self.newiface
            print '  [-]Del %s...' %self.newiface	    
            ShutdownIface(self.newiface)

        if self.savingPkt == '1': 
            print '\n[!]Analysing data...'
            Analysis(self.sfilename, self.iHost)
            print '\n[*]The name of Pkts dirPath is: ./Pkts/%s/' %putColor(self.sfilename, 'green')
            Abandon(self.sfilename, 'pkt')# Abandon this Pkts and Pcap?

        if self.savingPcap == '1': 
            print '\n[*]The name of Pcap is: ./Pcaps/%s' %putColor(self.sfilename, 'green')
            Abandon(self.sfilename, 'pcap')# Abandon this Pkts and Pcap?
        
        print '\n[!]All Done!'
        print '[*]' + putColor('Have a nice day~ :)', 'green')		

Sniffer()