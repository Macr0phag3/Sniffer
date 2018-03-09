from requests import *

cookies = dict(skey='@H4nhKgfLZ',
               uin = 'o0997334636',
               p_skey = 'Uk7Hakd*cpbialWutENOIccjbZPCwla6L0nLKIzVmF8_',
               p_uin = 'o097334636',        
               )

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'}
r = get('https://user.qzone.qq.com/997334636', cookies=cookies, headers=headers)
print r.text
for i in r.cookies: print i

