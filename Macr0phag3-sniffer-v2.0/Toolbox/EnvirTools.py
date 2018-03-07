#encoding: utf8
import commands
import sys


def CheckEnvir():
    try:
        import scapy
        import scapy_http.http as http
        from termcolor import colored
        return True
    except:
        print '[!]Oh, something went wrong!'
        if raw_input('[+]Maybe you want me to fix it? [y/n] ') == 'y':
            if autoFix(): return True
            
        return sys.exit(1)

def autoFix():
    try:
        print '  [-]Install scapy... ',
        commands.getoutput('sudo pip install scapy')
        print 'Successfully!'
        
        print '  [-]Install scapy-http... ',
        commands.getoutput('sudo pip install scapy-http')
        print 'Successfully!'
        
        print '  [-]Install termcolor... ', 
        commands.getoutput('sudo pip install termcolor')
        print 'Successfully!'
        
        from termcolor import colored
        print '[*]' + colored('Successfully!', color = 'green', attrs = ['bold']), '\n'
        return True
    
    except Exception, e:
        print '[!]Oops, Failed! You should fix it by yourself. Sorry :('
        print '  [-]Error:', e, '\n'
        return sys.exit(1)