#encoding: utf8
import re
import commands

def getInterface():
    return re.findall('([0-9a-zA-Z].+).+IEEE', commands.getoutput('iwconfig'))[-1]

def getLocalIP(iface):
    ip = re.findall('\s.+flags.+\s.+inet (.+)  net', commands.getoutput('ifconfig'))[-1]
    return ip

def StartIface(iface, newiface):
    commands.getoutput('iw dev %s interface add %s type monitor' %(iface, newiface))
    commands.getoutput('ifconfig %s up' %newiface)

def ShutdownIface(newiface):
    commands.getoutput('sudo ifconfig %s down' %newiface)
    commands.getoutput('sudo iw %s del' %newiface)   