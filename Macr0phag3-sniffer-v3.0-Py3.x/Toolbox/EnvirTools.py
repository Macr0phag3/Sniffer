#encoding: utf8
import subprocess
import sys


def CheckEnvir():
    Name = []
    try:
        import scapy
    except:
        Name.append('scapy')
    
    try:
        import scapy_http.http as http
    except:
        Name.append('scapy_http')
    
    try:
        from termcolor import colored
    except:
        Name.append('termcolor')
        
    if Name: 
        if not autoFix(Name): return False
    
    return True
    

def autoFix(Name):
    exitflag = 0
    print('[Uninstalled] %s' %(', '.join(Name)))
    
    if raw_input('[+]Maybe you want me to fix it? [y/n] ') != 'y':
        return False
    
    for name in Name:
        try:
            print('  [-]Install %s... ' %name,)
            sys.stdout.flush()
            result = subprocess.getoutput('sudo pip install %s' %name)
            if 'Successfully installed' in result:
                print('Successfully!')
            else:
                print('[Failed] You should install %s by yourself :(' %name)
                exitflag = 1
                
        except Exception as e:
            print('[!]Oops, Failed! You should fix it by yourself. Sorry :(')
            print('  [-]Error:', e, '\n')
            return False
    
    if exitflag: return False
    from termcolor import colored
    print('[*]' + colored('All Done!', color = 'green', attrs = ['bold']), '\n')
    return True        