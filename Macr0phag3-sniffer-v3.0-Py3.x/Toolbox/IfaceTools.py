#encoding: utf8
import re
import subprocess

def getInterface():
    return re.findall('([0-9a-zA-Z].+).+IEEE', subprocess.getoutput('iwconfig'))[-1]

def getLocalIP(iface):
    ip = re.findall('\s.+flags.+\s.+inet (.+)  net', subprocess.getoutput('ifconfig'))[-1]
    return ip

def StartIface(iface, newiface):
    subprocess.getoutput('iw dev %s interface add %s type monitor' %(iface, newiface))
    subprocess.getoutput('ifconfig %s up' %newiface)

def ShutdownIface(newiface):
    subprocess.getoutput('sudo ifconfig %s down' %newiface)
    subprocess.getoutput('sudo iw %s del' %newiface)   