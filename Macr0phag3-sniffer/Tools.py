#encoding: utf8
import re
import commands
import sys
import os
import SimpleHTTPServer
import SocketServer

def putColor(text, color):
    return colored(text, color = color, attrs = ['bold'])

def InitPktsFile(sfilename):
    os.mkdir('./Pkts/%s' %sfilename)  

def InitSrcIPFile(srcIP):
    pass

def getInterface():
    return re.findall('([0-9a-zA-Z].+).+IEEE', commands.getoutput('iwconfig'))[-1]
    
def getLocalIP(iface):
    ip = re.findall('\s.+flags.+\s.+inet (.+)  net', commands.getoutput('ifconfig'))[-1]
    return ip

def SavePkts(info, name, sfilename, srcIP, Host):
    #saving raw data
    with open('./Pkts/%s/raw_%s.txt' %(sfilename, name), 'a') as fp: 
        fp.write(info)
    
    s = './Pkts/%s/%s/%s' %(sfilename, srcIP, Host)
    if not os.path.exists(s): os.makedirs(s)

    with open('./Pkts/%s/%s/%s/%s.txt' %(sfilename, srcIP, Host, name), 'w') as fp: fp.write(info)

def StartIface(iface, newiface):
    commands.getoutput('iw dev %s interface add %s type monitor' %(iface, newiface))
    commands.getoutput('ifconfig %s up' %newiface)

def ShutdownIface(newiface):
    commands.getoutput('sudo ifconfig %s down' %newiface)
    commands.getoutput('sudo iw %s del' %newiface)    

def Clear(): sys.stdout.flush()

def Analysis(sfilename, iHost):
    cnum = pnum = Hostnum = 0

    filename = []
    srcIP = [i for i in os.listdir('./Pkts/%s' %sfilename) if 
             os.path.isdir('./Pkts/%s' %sfilename + '/' + i)]
    
    print '[*]Show Host:'
    for ip in srcIP:
        print '[' + putColor(ip, 'green') + ']'
        Host = os.listdir('./Pkts/%s/%s' %(sfilename, ip))
        Hostnum += len(Host)
        for host in Host:
            if host in iHost: print '  [-]' + putColor(host, 'red')
            else: print '  [-]' + host
            
            filename = os.listdir('./Pkts/%s/%s/%s' %(sfilename, ip, host))
            if 'Cookie.txt' in filename: cnum += 1
            if 'POST.txt' in filename: pnum += 1
    
    print '\n[+]Info:'        
    print '  [-]%s' %putColor('%s: %d' %('srcIP', len(srcIP)), 'blue')
    print '  [-]%s' %putColor('%s: %d' %('Host', Hostnum), 'white')
    print '  [-]%s' %putColor('%s: %d' %('Cookie', cnum), 'cyan')
    print '  [-]%s' %putColor('%s: %d' %('PostData', pnum), 'yellow')
     
    
def Abandon(sfilename, tfile):
    if tfile == 'pkt':
        if raw_input('[!]%s [yes: yes/others: no]: ' %(putColor('Abandon this Pkts file?', 'red'))) == "yes": 
            commands.getoutput('sudo rm -r ./Pkts/%s/' %(sfilename))
            print '  [-]%s' %putColor('Pkts deletion has completed successfully!', 'yellow')
    elif tfile == 'pcap': 
        if raw_input('[!]%s [yes: yes/others: no]: ' %(putColor('Abandon this Pcap file?', 'red'))) == "yes": 
            commands.getoutput('sudo rm ./Pcaps/%s.pcap' %(sfilename))
            print '  [-]%s' %putColor('Pcaps deletion has completed successfully!', 'yellow')    

    
def HtmlShow(name):  
    print '[+]Html'
    m = "<a href='http://%s' target='show'>%s</a>"

    for i in name:
        with open('./Pkts/' + i + '/Cookie.txt', 'r') as fp:
            data = fp.read()
            Host = re.findall('\[-\]Host: (.+)', data)
            Cookie = re.findall('\[-\]Cookie: (.+)', data)
        
        print len(Host)
        print len(Cookie)
        with open('./www/frame/urls.html', 'w') as fp:
            fp.write("""<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n<title>Show</title>\n<body>\n\n""")
            
        with open('./www/frame/urls.html', 'a') as fp:
            for i in xrange(len(Host)):
                fp.write("<a href='http://%s' target='show'>%s</a><br>\n" %(Host[i], Host[i]))
            fp.write('</body>\n</html>')


#Satrt a www service...
#This is in the TODO list.
def HttpServer(port):
    import SimpleHTTPServer
    import SocketServer

    
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", port), Handler)
    
    print "serving at port", port
    httpd.serve_forever()    




#Check for your packages.
try:
    import scapy
    import scapy_http.http as http
    from termcolor import colored
    
except:
    print '[!]Oh, something went wrong!'
    if raw_input('[+]Maybe you want to fix it? [y/n]') == 'y':
        try:
            print commands.getoutput('sudo pip install scapy')
            print commands.getoutput('sudo pip install scapy-http')
            print commands.getoutput('sudo pip install termcolor')
            from termcolor import colored
            print '[*]' + colored('All Done', color = color, attrs = ['bold'])
        
        except Exception, e:
            print '[!]Oops, Failed! It looks you should fix it by yourself. Sorry :('
            print '  [-]', e
            sys.exit(1)