import sys
import zlib
import json
import getopt
import requests
import traceback
import threading
from bs4 import BeautifulSoup

def Whois1_internic(simple_url):#利用internic进行Whois查询
    lock.acquire()
    try:
        print('\n[!] 正在使用internic进行Whois信息查询 ……')
        headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36',
        'Referer':'https://www.internic.net/'
        }
        requests_internic = requests.get('https://reports.internic.net/cgi/whois?whois_nic={}&type=domain'.format(simple_url),headers=headers)
        bs4_requests_internic = BeautifulSoup(requests_internic.text,'html.parser')
        for i in bs4_requests_internic.select('pre')[0].text.split('>>>')[0].split('\n'):
            if i not in '':
                print('[+]    ',i.split('   ')[1])
    except Exception as e:
        print('[-] 发生异常:',e,'程序正在退出……')
        sys.exit()
    lock.release()
    
    
def Whois2_chinaz(simple_url):#利用站长之家进行Whois查询
    lock.acquire()
    try:
        print('\n[!] 正在使用站长之家进行Whois信息查询 ……')
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36'}
        requests_chinaz = requests.get('https://whois.chinaz.com/{}'.format(simple_url),headers=headers)
        bs4_requests_chinaz = BeautifulSoup(requests_chinaz.text,'html.parser')
        bs4_Whois_info_chinaz = bs4_requests_chinaz.select('#sh_info')[0].select('.bor-b1s')
        for i in bs4_Whois_info_chinaz:
            if '域名' not in i.text and '站长之家' not in i.text:
                print('[+]    ',i.text.replace('[whois反查]',''))
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')   
        sys.exit()
    lock.release()
       
        
def beian(url):
    lock.acquire()
    try:
        print('\n[!] 正在使用站长之家进行域名备案信息查询 ……')
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36'}
        requests_beian = requests.get('https://icp.chinaz.com/info?q={}'.format(url),headers = headers)
        bs_beian = BeautifulSoup(requests_beian.text,'html.parser')
        H1_beian = bs_beian.select('.Imgicp-right')[0].select('.text')
        H2_beian = bs_beian.select('.Imgicp-right')[0].select('.bx')
        H3_1_beian = bs_beian.select('.Imgicp-right')[0].select('.by1')
        H3_2_beian = bs_beian.select('.Imgicp-right')[0].select('.by2')
        print('[+] ',H1_beian[0].text,':')
        print('[+]     ',H2_beian[0].text,H3_1_beian[0].text)
        print('[+]     ',H2_beian[1].text,H3_2_beian[0].text)
        print('[+]     ',H2_beian[2].text,H3_1_beian[1].text)
        print('[+]     ',H2_beian[3].text,H3_2_beian[1].text)
        print('[+] ',H1_beian[1].text,':')
        print('[+]     ',H2_beian[4].text,H3_1_beian[2].text)
        print('[+]     ',H2_beian[5].text,H3_2_beian[2].text)
        print('[+]     ',H2_beian[6].text,H3_1_beian[3].text)
        print('[+]     ',H2_beian[7].text,H3_1_beian[4].text.split()[0])
        print('[+]     ',H2_beian[8].text,H3_1_beian[5].text)
        print('[+]     ',H2_beian[9].text,H3_1_beian[6].text.split()[0])
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')    
        sys.exit()
    lock.release()
    
    
def CMS1_yunsee(complete_url):#CMS1_云悉
    lock.acquire()
    try:
        print('\n[!] 正在使用云悉进行CMS指纹信息识别 ……')
        headers = {
            'Accept': '*/*',
            'Origin': 'http://www.yunsee.cn',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': 'http://www.yunsee.cn/info.html',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close'
        }
        data = {'type':'webinfo','url':complete_url}
        response_yunsee = requests.post('http://www.yunsee.cn/home/getInfo',headers=headers,data=data)
        response_yunsee_text = json.loads(response_yunsee.text)
        global print_yunsee
        print_yunsee = response_yunsee_text['res']
        if 'success' == response_yunsee_text['mess']:
            for i in print_yunsee['fingers']:
                if i not in 'id':
                    print('[+]',i)
                    for j in print_yunsee['fingers'][i]:
                        print('[+]    ',j)
        else:
            print('[-] 来自云悉的提示:',response_yunsee_text['mess'])
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')    
        sys.exit()
    lock.release()


def CMS2_bugscaner(complete_url):#CMS2_bugscaner
    lock.acquire()
    try:
        print('\n[!] 正在使用bugscaner进行CMS指纹信息识别 ……')
        response_bugscaner = requests.get(complete_url)
        whatweb_dict = {"url":response_bugscaner.url,"text":response_bugscaner.text,"headers":dict(response_bugscaner.headers)}
        whatweb_dict = json.dumps(whatweb_dict)
        whatweb_dict = whatweb_dict.encode()
        whatweb_dict = zlib.compress(whatweb_dict)
        data = {"info":whatweb_dict}

        request_bugscaner = requests.post("http://whatweb.bugscaner.com/api.go",files=data)
        print('[!] 来自bugscaner的提示，今日识别剩余次数：',request_bugscaner.headers["X-RateLimit-Remaining"])
        for i in request_bugscaner.json():
            print('[+]    ',i,':',request_bugscaner.json()[i])
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')     
        sys.exit()
    lock.release()


def dnsdumpster(simple_url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://dnsdumpster.com/'
        }
        cookies = {'csrftoken': '4tJuOfVPT4wFkMQOEwNEvLTSgyFcIiPOeTaoBmJXlbvUUOCOC9nRyuhZjpNGWh4I'}
        data = {'csrfmiddlewaretoken': '1R9Juuje25Pb3yx3YPG5TbXvdvbXMzGmbhADhB7mucOqDAj3WsgiWUlCgmjr0yVg',
                'targetip': simple_url}
        requests_dnsdumpster = requests.post('https://dnsdumpster.com/', headers=headers, cookies=cookies, data=data)
        bs_requests_dnsdumpster = BeautifulSoup(requests_dnsdumpster.text, 'html.parser')
        global H1_dnsdumpster, H2_dnsdumpster, H2_1_dnsdumpster
        H1_dnsdumpster = bs_requests_dnsdumpster.select('p')
        H2_dnsdumpster = bs_requests_dnsdumpster.select('.table-responsive')
        H2_1_dnsdumpster = H2_dnsdumpster[3].select('td')
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')
        sys.exit()

def ip1_dnsdumpster(simple_url):
    lock.acquire()
    try:
        dnsdumpster(simple_url)
        print('\n[!] 正在使用dnsdumpster进行IP地址查询 ……')
        print('[!] 注意：如果目标使用了CDN，那么查询到的IP不可信')
        for j in range(3):
            print('[+]     ',H2_1_dnsdumpster[j].text.split())
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')       
        sys.exit()
    lock.release()

def ip2_aizhan(simple_url):
    lock.acquire()
    try:
        print('\n[!] 正在使用爱站网进行IP地址查询 ……')
        print('[!] 注意：如果两次查询的IP不一致，那么查询到的IP不可信')
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0'}
        requests_aizhan = requests.get('https://dns.aizhan.com/{}/'.format(simple_url),headers = headers)
        bs_aizhan = BeautifulSoup(requests_aizhan.text,'html.parser')
        for i in range(3):
            print('[+] ',bs_aizhan.select('p')[i+1].text,':',bs_aizhan.select('strong')[i].text)
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')       
        sys.exit()
    lock.release()
        
    
def tianyancha(url):
    lock.acquire()
    try:
        print('\n[!] 正在使用天眼查进行资产查询 ……')
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
                    'Referer':'https://www.tianyancha.com/search?key={}'.format(url)}
        requests_tianyancha = requests.get('https://www.tianyancha.com/search?key={}'.format(url),headers = headers)
        bs_requests_tianyancha = BeautifulSoup(requests_tianyancha.text,'html.parser')
        list_tianyancha = bs_requests_tianyancha.select('.search-result-single')#获取主页查询结果
        if list_tianyancha != []:
            print('[!] 注意：因为天眼查存在反爬机制，因此回显结果可能存在问题')
            sub_url = list_tianyancha[0].a['href']#获取列表中的第一个结果
            sub_requests_tianyancha = requests.get(sub_url,headers = headers)
            sub_bs_requests_tianyancha = BeautifulSoup(sub_requests_tianyancha.text,'html.parser')
            targetname_tianyancha = sub_bs_requests_tianyancha.select('.name')[0].text
            targeturl_tianyancha = sub_bs_requests_tianyancha.select('.in-block.sup-ie-company-header-child-1')[1].text#获取目标公司的URL
            targetinfo_tianyancha = sub_bs_requests_tianyancha.select('.table.-striped-col.-border-top-none.-breakall')[0].select('td')
            print('\n[+] 公司名称：',targetname_tianyancha)
            print('[+]',targeturl_tianyancha)
            for i in range(0,40,2):
                if i < 4:
                    print('[+]',targetinfo_tianyancha[i].text,':',targetinfo_tianyancha[i+1].text)
                if i > 4:
                    print('[+]',targetinfo_tianyancha[i-1].text,':',targetinfo_tianyancha[i].text)
            print('\n[+] 关于该URL的其他可能相关资产信息如下：')
            for i in list_tianyancha:
                print('[+] ',i.a['href'])
        else:
            print('[-] 未查询到该URL的企业信息')
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')       
        sys.exit()
    lock.release()

def DNSinfo():
    lock.acquire()
    try:
        print('\n[!] 正在使用dnsdumpster进行DNS信息查询 ……')
        dnsdumpster(simple_url)
        for i in range(3): #DNS信息查询
            print('\n[+] ',H1_dnsdumpster[i+4].text)
            for j in H2_dnsdumpster[i].select('td'):
                print('[+]     ',j.text.split())
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')       
        sys.exit()
    lock.release()

def SubDomain():
    lock.acquire()
    try:
        print('\n[!] 正在使用dnsdumpster进行子域名查询 ……')
        dnsdumpster(simple_url)
        for j in range(3,len(H2_1_dnsdumpster)):
            print('[+]     ',H2_1_dnsdumpster[j].text.split())
    except Exception as e:
        print ('[-] 发生异常:',e,'程序正在退出……')     
        sys.exit()
    lock.release()
  

def deal_url(url):
    global simple_url,complete_url,t_whois1, t_whois2, t_beian, t_cms1, t_cms2, t_ip1, t_ip2, t_DNSinfo, t_SubDomain, t_zhichan, threading_list
    if 'www' in url: # 将url格式处理成简单的url
        simple_url = '.'
        simple_url = simple_url.join(url.split('.')[1:]) 
    elif '/' in url:
        simple_url = url.split('/')[2]
    else:
        simple_url = url

    if '/' not in url: # 将url格式处理成完整的url
        complete_url = 'http://' + url
    else:
        complete_url = url

    t_whois1 = threading.Thread(target = Whois1_internic,args = (simple_url,),name = 'whois1')#Whois1_internic
    t_whois2 = threading.Thread(target = Whois2_chinaz,args = (simple_url,),name = 'whois2')#Whois2_站长之家
    t_beian = threading.Thread(target = beian,args = (url,),name = 'beian')#站长之家备案信息查询
    t_cms1 = threading.Thread(target = CMS1_yunsee,args = (complete_url,),name = 'cms1')#CMS1_云悉
    t_cms2 = threading.Thread(target = CMS2_bugscaner,args = (complete_url,),name = 'cms2')#CMS2_bugscaner
    t_ip1 = threading.Thread(target = ip1_dnsdumpster,args = (simple_url,),name = 'ip1')#ip1_dnsdumpsterc
    t_ip2 = threading.Thread(target = ip2_aizhan,args = (simple_url,),name = 'ip2')#ip1_爱站网
    t_DNSinfo = threading.Thread(target = DNSinfo,name = 'DNSinfo')#DNS信息
    t_SubDomain = threading.Thread(target = SubDomain,name = 'SubDomain')#子域名
    t_zhichan = threading.Thread(target = tianyancha,args = (url,),name = 'tianyancha')#天眼查

    threading_list = [t_whois1,t_whois2,t_beian,t_cms1,t_cms2,t_ip1,t_ip2,t_DNSinfo,t_SubDomain,t_zhichan]
  
               
if __name__ == '__main__':
    try:
        print(
'''
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                       *
 *               【被动信息收集聚合工具】                *
 *    Passive Intelligence Gathering Aggregation Tool    *
 *                                                       *
 *    示例格式：python pigat.py -u teamssix.com          *
 *    查看帮助：python pigat.py -h                       *
 *                                                       *
 *                     【关于作者】                      *
 *                   公众号：TeamsSix                    *
 *                  博客：teamssix.com                   *
 *                                                       *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
'''
)
        lock = threading.Lock()
        argv = sys.argv[1:]
        if argv == []:
            print('\n[-] 请参考上面的示例格式输入正确内容，或者查看帮助\n')
            sys.exit()
        opts,args = getopt.getopt(argv,'hu:',['help','url=','whois','filing','cms','ip','dns','subdomain','assert'])
        
    except getopt.GetoptError:
        print('''
[-] 请参考帮助信息输入正确格式内容

    帮助：
        --assert : 搜集目标资产信息
        --cms : 搜集目标CMS信息
        --dns : 搜集目标DNS信息
        --filing : 搜集目标备案信息
        -h | --help ：查看帮助信息
        --ip : 搜集目标IP信息   
        --subdomain : 搜集目标子域名信息
        -u | --url : 指定目标URL，默认收集所有信息
        --whois : 搜集目标Whois信息

    示例：
        python pigat.py -h：查看帮助信息
        python pigat.py -u teamssix.com ：查看teamssix.com的所有信息
        python pigat.py -u teamssix.com --assert：查看teamssix.com的相关资产信息
        ''')
        sys.exit(2)
        
    for opt,arg in opts:
        if opt in ('-h','--help'):
            print('''
帮助：
    --assert : 搜集目标资产信息
    --cms : 搜集目标CMS信息
    --dns : 搜集目标DNS信息
    --filing : 搜集目标备案信息
    -h | --help ：查看帮助信息
    --ip : 搜集目标IP信息   
    --subdomain : 搜集目标子域名信息
    -u | --url : 指定目标URL，默认收集所有信息
    --whois : 搜集目标Whois信息
                
示例：
    python pigat.py -h：查看帮助信息
    python pigat.py -u teamssix.com ：查看teamssix.com的所有信息
    python pigat.py -u teamssix.com --assert：查看teamssix.com的相关资产信息
                ''')
            sys.exit()
        elif opt in ('-u','--url'): # 指定url
            url = arg
            deal_url(url)
            if len(argv) == 2:#搜索所有信息
                for i in threading_list:
                    i.start()
                for i in threading_list:
                    i.join()
        elif opt in ('--assert'): # 搜索资产信息
            t_zhichan.start()
            t_zhichan.join()
        elif opt in ('--cms'): # 搜索CMS信息
            t_cms1.start()
            t_cms2.start()
            t_cms1.join()
            t_cms2.join()
        elif opt in ('--dns'): # 搜索DNS信息
            t_DNSinfo.start()
            t_DNSinfo.join()
        elif opt in ('--filing'): # 搜索备案信息
            t_beian.start()
            t_beian.join()
        elif opt in ('--ip'): # 搜索IP信息
            t_ip1.start()
            t_ip2.start()
            t_ip1.join()   
            t_ip2.join() 
        elif opt in ('--subdomain'): # 搜索子域名信息
            t_SubDomain.start()
            t_SubDomain.join() 
        elif opt in ('--whois'): # 搜索whois信息
            t_whois1.start()
            t_whois2.start()
            t_whois1.join()  
            t_whois2.join()         
