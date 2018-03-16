#encoding: utf8
import os
from Toolbox.ColorTools import *
import subprocess
import time
import traceback

def InitPktsFile(sfilename):
    os.mkdir('./Pkts/%s' %sfilename)  
    
def ErrorDog(Exit):
    error = '\n'.join(['\n[X]%s' %putColor('Something went wrong', 'red'),
                       '  [-]'+putColor('Time: ', 'yellow')+putColor(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()),'green'),
                       '  [-]'+putColor('Exception: \n', 'yellow')+putColor(str(traceback.format_exc())[:-1], 'white'),
                       '-'*50, 
                       ])
    
    with open('Log.here', 'a') as fp:
        fp.write(Eraser(error))
        
    print(error)
    sys.exitfunc = Exit
    sys.exit(1)
    
    
def SavePkts(info, name, sfilename, srcIP, Host):
    #saving raw data
    with open('./Pkts/%s/raw_%s.txt' %(sfilename, name), 'a') as fp: fp.write(info)
    
    s = './Pkts/%s/%s/%s' %(sfilename, srcIP, Host)
    if not os.path.exists(s): os.makedirs(s)

    with open('./Pkts/%s/%s/%s/%s.txt' %(sfilename, srcIP, Host, name), 'w') as fp: fp.write(info)
    

def Analysis(sfilename, iHost):
    cnum = pnum = Hostnum = 0

    filename = []
    srcIP = [i for i in os.listdir('./Pkts/%s' %sfilename) if 
             os.path.isdir('./Pkts/%s' %sfilename + '/' + i)]
    
    print('[*]Show Host:')
    for ip in srcIP:
        print('[' + putColor(ip, 'green') + ']')
        Host = os.listdir('./Pkts/%s/%s' %(sfilename, ip))
        Hostnum += len(Host)
        for host in Host:
            if host in iHost: print('  [-]' + putColor(host, 'red'))
            else: print('  [-]' + host)
            
            filename = os.listdir('./Pkts/%s/%s/%s' %(sfilename, ip, host))
            if 'Cookie.txt' in filename: cnum += 1
            if 'POST.txt' in filename: pnum += 1
    
    print('\n[+]Info:'        )
    print('  [-]%s' %putColor('%s: %d' %('srcIP', len(srcIP)), 'blue'))
    print('  [-]%s' %putColor('%s: %d' %('Host', Hostnum), 'white'))
    print('  [-]%s' %putColor('%s: %d' %('Cookie', cnum), 'cyan'))
    print('  [-]%s' %putColor('%s: %d' %('PostData', pnum), 'yellow'))
    
    
def Abandon(sfilename, tfile):
    if tfile == 'pkt':
        if input('[!]%s [yes: yes/others: no]: ' %(putColor('Abandon this Pkts file?', 'red'))) == "yes": 
            subprocess.getoutput('sudo rm -r ./Pkts/%s/' %(sfilename))
            print('  [-]%s' %putColor('Pcaps deletion has completed successfully!', 'yellow'))
    elif tfile == 'pcap': 
        if input('[!]%s [yes: yes/others: no]: ' %(putColor('Abandon this Pcap file?', 'red'))) == "yes": 
            subprocess.getoutput('sudo rm ./Pcaps/%s.pcap' %(sfilename))
            print('  [-]%s' %putColor('Pkts deletion has completed successfully!', 'yellow')    )
    
    
    
    
    
    
    
    