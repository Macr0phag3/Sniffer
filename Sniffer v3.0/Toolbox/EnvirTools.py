#encoding: utf8
import commands
import sys
import pip

def CheckEnvir():
    modules = ['argparse',
            'scapy',
            'scapy_http',
            'termcolor'
            ]
    
    Name = []
    for module in modules:  
        try:  
            __import__(module)
        except:  
            Name.append(module)
        
    if Name: 
        if not autoFix(Name): return False
    
    return True
    

def autoFix(Name):
    exitflag = 0
    print '[Uninstalled] %s' %(', '.join(Name))
    
    if raw_input('[+]Maybe you want me to fix it? [y/n] ') != 'y':
        return False
    
    for name in Name:
        try:
            print '  [-]Install %s... ' %name,
            sys.stdout.flush()
            result = commands.getoutput('sudo pip install %s' %name)
            if 'Successfully installed' or 'satisfied' in result:
                print 'Successfully!'
            else:
                print '[Failed] You should install %s by yourself :(' %name
                exitflag = 1
                
        except Exception, e:
            print '[!]Oops, Failed! You should fix it by yourself. Sorry :('
            print '  [-]Error:', e, '\n'
            return False
    
    if exitflag: return False
    from termcolor import colored
    print '[*]' + colored('All Done!', color = 'green', attrs = ['bold']), '\n'
    return True        