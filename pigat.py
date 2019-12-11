import re
import sys
import zlib
import json
import getopt
import requests
import traceback
import threading
import pandas as pd
from bs4 import BeautifulSoup
from texttable import Texttable

def Whois1_internic(simple_url):#利用internic进行Whois查询
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用internic进行Whois信息查询 ……\033[0m')
        headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36',
        'Referer':'https://www.internic.net/'
        }
        requests_internic = requests.get('https://reports.internic.net/cgi/whois?whois_nic={}&type=domain'.format(simple_url),headers=headers)
        bs4_requests_internic = BeautifulSoup(requests_internic.text,'html.parser')
        result_internic = bs4_requests_internic.select('pre')[0].text.split('>>>')[0].split('\n')
        if 'No match for domain' in result_internic[1]:
            print('\033[1;31;40m[-] {}\033[0m'.fotmat(result_internic[1]))
        else:
            for i in result_internic:
                if i not in '':
                    print('\033[1;32;40m[+] {}\033[0m'.format(i.split('   ')[1]))
    except Exception as e:
        print('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()
    
    
def Whois2_chinaz(simple_url):#利用站长之家进行Whois查询
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用站长之家进行Whois信息查询 ……\033[0m')
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36'}
        requests_chinaz = requests.get('https://whois.chinaz.com/{}'.format(simple_url),headers=headers)
        bs4_requests_chinaz = BeautifulSoup(requests_chinaz.text,'html.parser')
        check_chinaz = bs4_requests_chinaz.select('.fz18')[0].text
        if check_chinaz == '该域名被屏蔽':
            print('\033[1;31;40m[-] 该域名已被站长之家屏蔽\033[0m')
        else:
            bs4_Whois_info_chinaz = bs4_requests_chinaz.select('#sh_info')[0].select('.bor-b1s')
            for i in bs4_Whois_info_chinaz:
                if '域名' not in i.text and '站长之家' not in i.text:
                    print('\033[1;32;40m[+] {}\033[0m'.format(i.text.replace('[whois反查]', '')))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:\033[0m'.format(e))
    lock.release()
       
        
def beian(url):
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用站长之家进行域名备案信息查询 ……\033[0m')
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36'}
        requests_beian = requests.get('https://icp.chinaz.com/info?q={}'.format(url),headers = headers)
        bs_beian = BeautifulSoup(requests_beian.text,'html.parser')
        H1_beian = bs_beian.select('.Imgicp-right')[0].select('.text')
        H2_beian = bs_beian.select('.Imgicp-right')[0].select('.bx')
        H3_1_beian = bs_beian.select('.Imgicp-right')[0].select('.by1')
        H3_2_beian = bs_beian.select('.Imgicp-right')[0].select('.by2')
        print('\033[1;32;40m[+] {}\033[0m'.format(H1_beian[0].text,':'))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[0].text,H3_1_beian[0].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[1].text,H3_2_beian[0].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[2].text,H3_1_beian[1].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[3].text,H3_2_beian[1].text))
        print('\033[1;32;40m[+] {}\033[0m'.format(H1_beian[1].text,':'))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[4].text,H3_1_beian[2].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[5].text,H3_2_beian[2].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[6].text,H3_1_beian[3].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[7].text,H3_1_beian[4].text.split()[0]))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[8].text,H3_1_beian[5].text))
        print('\033[1;32;40m[+]    {}\033[0m'.format(H2_beian[9].text,H3_1_beian[6].text.split()[0]))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()
    
    
def CMS1_yunsee(complete_url):#CMS1_云悉
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用云悉进行CMS指纹信息识别 ……\033[0m')
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
        data = {'type': 'webcms', 'url': complete_url}
        response_yunsee = requests.post('http://www.yunsee.cn/home/getInfo', headers=headers, data=data)
        response_yunsee_text = json.loads(response_yunsee.text)
        if response_yunsee_text['code'] == 1:
            print_yunsee = response_yunsee_text['res']
            for i in print_yunsee:
                print('\033[1;32;40m[+] {} ({})\033[0m'.format(i['name'], i['desc']))
        else:
            print('\033[1;31;40m[-] 来自云悉的提示:{} 请过会儿后重试\033[0m'.format(response_yunsee_text['mess']))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()


def CMS2_bugscaner(complete_url):#CMS2_bugscaner
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用bugscaner进行CMS指纹信息识别 ……\033[0m')
        response_bugscaner = requests.get(complete_url)
        whatweb_dict = {"url":response_bugscaner.url,"text":response_bugscaner.text,"headers":dict(response_bugscaner.headers)}
        whatweb_dict = json.dumps(whatweb_dict)
        whatweb_dict = whatweb_dict.encode()
        whatweb_dict = zlib.compress(whatweb_dict)
        data = {"info":whatweb_dict}

        request_bugscaner = requests.post("http://whatweb.bugscaner.com/api.go",files=data)
        print('\033[1;33;40m[!] 来自bugscaner的提示，今日识别剩余次数：{}\033[0m '.format(request_bugscaner.headers["X-RateLimit-Remaining"]))
        for i in request_bugscaner.json():
            print('\033[1;32;40m[+] {}:{}\033[0m'.format(i,request_bugscaner.json()[i]))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
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
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
        

def ip1_dnsdumpster(simple_url):
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用dnsdumpster进行IP地址查询 ……\033[0m ')
        print('\033[1;33;40m[!] 注意：如果目标使用了CDN，那么查询到的IP不可信\033[0m ')
        dnsdumpster(simple_url)
        if H2_1_dnsdumpster == []:
            print('\033[1;31;40m[-] 查询结果为空\033[0m ')
        else:
            for j in range(3):
                print('\033[1;32;40m[+] {}\033[0m'.format(H2_1_dnsdumpster[j].text.split()))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()

def ip2_aizhan(medium_url):
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用爱站网进行IP地址查询 ……\033[0m ')
        print('\033[1;33;40m[!] 注意：如果两次查询的IP不一致，那么查询到的IP不可信\033[0m ')
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0'}
        requests_aizhan = requests.get('https://dns.aizhan.com/{}/'.format(medium_url),headers = headers)
        bs_aizhan = BeautifulSoup(requests_aizhan.text,'html.parser')
        judge_bs_aizhan = bs_aizhan.select('.red')[0].text
        if judge_bs_aizhan != '解析域名失败!':
            global ip_bs_aizhan
            ip_bs_aizhan = bs_aizhan.select('strong')
            for i in range(3):
                print('\033[1;32;40m[+] {}:{}\033[0m'.format(bs_aizhan.select('p')[i + 1].text,ip_bs_aizhan[i].text))
        else:
            print('\033[1;31;40m[-] {}\033[0m'.format(judge_bs_aizhan))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()
        
    
def tianyancha(url):
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用天眼查进行资产查询 ……\033[0m ')
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
                    'Referer':'https://www.tianyancha.com/search?key={}'.format(url)}
        requests_tianyancha = requests.get('https://www.tianyancha.com/search?key={}'.format(url),headers = headers)
        bs_requests_tianyancha = BeautifulSoup(requests_tianyancha.text,'html.parser')
        list_tianyancha = bs_requests_tianyancha.select('.search-result-single')#获取主页查询结果
        if list_tianyancha != []:
            print('\033[1;33;40m[!] 注意：因为天眼查存在反爬机制，因此回显结果可能存在问题\033[0m ')
            sub_url = list_tianyancha[0].a['href']#获取列表中的第一个结果
            sub_requests_tianyancha = requests.get(sub_url,headers = headers)
            sub_bs_requests_tianyancha = BeautifulSoup(sub_requests_tianyancha.text,'html.parser')
            targetname_tianyancha = sub_bs_requests_tianyancha.select('.name')[0].text
            targeturl_tianyancha = sub_bs_requests_tianyancha.select('.in-block.sup-ie-company-header-child-1')[1].text#获取目标公司的URL
            targetinfo_tianyancha = sub_bs_requests_tianyancha.select('.table.-striped-col.-border-top-none.-breakall')[0].select('td')
            print('\033[1;32;40m[+] 公司名称：{}\033[0m'.format(targetname_tianyancha))
            print('\033[1;32;40m[+] {}\033[0m'.format(targeturl_tianyancha))
            for i in range(0,40,2):
                if i < 4:
                    print('\033[1;32;40m[+] {}:{}\033[0m'.format(targetinfo_tianyancha[i].text,targetinfo_tianyancha[i+1].text))
                if i > 4:
                    print('\033[1;32;40m[+] {}:{}\033[0m'.format(targetinfo_tianyancha[i-1].text,targetinfo_tianyancha[i].text))
            print('\n\033[1;32;40m[+] 关于该URL的其他可能相关资产信息如下：\033[0m')
            for i in list_tianyancha:
                print('\033[1;32;40m[+] {}\033[0m'.format(i.a['href']))
        else:
            print('\033[1;31;40m[-] 未查询到该URL的企业信息\033[0m ')
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()

def DNSinfo():
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用dnsdumpster进行DNS信息查询 ……\033[0m ')
        dnsdumpster(simple_url)
        for i in range(3): #DNS信息查询
            print('\n\033[1;32;40m[+]{}\033[0m'.format(H1_dnsdumpster[i+4].text))
            for j in H2_dnsdumpster[i].select('td'):
                print('\033[1;32;40m[+]     {}\033[0m'.format(j.text.split()))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()

def SubDomain():
    lock.acquire()
    try:
        print('\n\033[1;33;40m[!] 正在使用dnsdumpster进行子域名查询 ……\033[0m ')
        dnsdumpster(simple_url)
        for i in range(3, len(H2_1_dnsdumpster),3):
            temp_subdomain = H2_1_dnsdumpster[i].text.split()
            print('\033[1;32;40m[+] {}\033[0m'.format(temp_subdomain[0]))
            for j in range(1, len(temp_subdomain), 1):
                print('\033[1;32;40m[+]     {}\t\033[0m'.format(temp_subdomain[j].replace(':', '')))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()

def port(ip,port):
    lock.acquire()
    try:
        url = 'http://tool.cc/port/check_port_status.php?remoteip={}&port={}'.format(ip,port)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0'}
        requests_port =  requests.get(url,headers = headers)
        if '打开' in requests_port.text:
            bs_port = BeautifulSoup(requests_port.text,'html.parser')
            print('\033[1;32;40m[+] {}  {}\033[0m'.format(port,bs_port.text))
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
    lock.release()

def port_main():
    try:
        print('\n\033[1;33;40m[!] 正在使用tool.cc进行端口查询 ……\033[0m ')
        if H2_1_dnsdumpster == []:
            print('\033[1;31;40m[-] dnsdumpster的查询结果为空，无法判断IP真实性，停止被动端口扫描……\033[0m ')
        else:
            if re.findall(r'(?<=>).*?(?=<br)',str(H2_1_dnsdumpster[1]))[0] == ip_bs_aizhan[1].text: #使用正则匹配结果，避免误报
                ip = ip_bs_aizhan[1].text
                print('\033[1;33;40m[!] 正在对{}进行常用端口查询 ……\033[0m '.format(ip))
                port_list = [21,22,23,25,53,80,110,135,137,138,139,143,443,445,1433,1863,2289,3306,3389,5631,5632,5000,8080,9090]
                thread_port = []
                for i in port_list:
                    t_port = threading.Thread(target = port,args = (ip,i,),name = 'port{}'.format(i))
                    thread_port.append(t_port)
                for i in thread_port:
                    i.start()
                for i in thread_port:
                    i.join()
            else:
                print('\033[1;31;40m[-] 发现两次IP查询的结果不一致，停止被动端口扫描……\033[0m ')
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
        

def deal_url(url):
    try:
        global simple_url,medium_url,complete_url,t_whois1, t_whois2, t_beian, t_cms1, t_cms2, t_ip1, t_ip2, t_DNSinfo, t_SubDomain, t_zhichan, threading_list
        if 'www' in url: # 将url格式处理成简单的url
            simple_url = '.'
            simple_url = simple_url.join(url.split('.')[1:])
        elif '//' in url:
            simple_url = url.split('//')[1]
        else:
            simple_url = url

        if '//' not in url and 'www' not in url:  # 将url格式处理成没有http://的url
            medium_url = 'www.' + url
        elif '//' in url and 'www' not in url:
            medium_url = 'www.' + url.split('//')[1]
        elif '//' in url and 'www' in url:
            medium_url = url.split('//')[1]
        else:
            medium_url = url

        if '//' not in url and 'www' not in url:  # 将url格式处理成完整的url
            complete_url = 'http://www.' + url
        elif '//' not in url:  # 将url格式处理成完整的url
            complete_url = 'http://' + url
        else:
            complete_url = url

        t_whois1 = threading.Thread(target = Whois1_internic,args = (simple_url,),name = 'whois1')#Whois1_internic
        t_whois2 = threading.Thread(target = Whois2_chinaz,args = (simple_url,),name = 'whois2')#Whois2_站长之家
        t_beian = threading.Thread(target = beian,args = (url,),name = 'beian',daemon=True)#站长之家备案信息查询
        t_cms1 = threading.Thread(target = CMS1_yunsee,args = (complete_url,),name = 'cms1')#CMS1_云悉
        t_cms2 = threading.Thread(target = CMS2_bugscaner,args = (complete_url,),name = 'cms2')#CMS2_bugscaner
        t_ip1 = threading.Thread(target = ip1_dnsdumpster,args = (simple_url,),name = 'ip1')#ip1_dnsdumpsterc
        t_ip2 = threading.Thread(target = ip2_aizhan,args = (medium_url,),name = 'ip2')#ip1_爱站网
        t_DNSinfo = threading.Thread(target = DNSinfo,name = 'DNSinfo')#DNS信息
        t_SubDomain = threading.Thread(target = SubDomain,name = 'SubDomain')#子域名
        t_zhichan = threading.Thread(target = tianyancha,args = (url,),name = 'tianyancha')#天眼查

        threading_list = [t_whois1,t_whois2,t_beian,t_zhichan,t_cms1,t_cms2,t_DNSinfo,t_SubDomain,t_ip1,t_ip2]
        for i in threading_list:
            i.setDaemon(True)
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
  
               
if __name__ == '__main__':
    try:
        print(
'''\033[1;33;40m
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
\033[0m'''
)
        lock = threading.Lock()
        argv = sys.argv[1:]
        if argv == []:
            print('\n\033[1;31;40m[-] 请参考上面的示例格式输入正确内容，或者查看帮助\033[0m \n')
            
        opts,args = getopt.getopt(argv,'hu:',['help','url=','whois','filing','cms','ip','dns','subdomain','assert','port'])
        
    except getopt.GetoptError:
        print('''
\033[1;31;40m[-] 请参考帮助信息输入正确格式内容

    帮助：
        --assert : 搜集目标资产信息
        --cms : 搜集目标CMS信息
        --dns : 搜集目标DNS信息
        --filing : 搜集目标备案信息
        -h | --help ：查看帮助信息
        --ip : 搜集目标IP信息
        --port : 如果两次查询IP结果一致，则扫描该IP端口
        --subdomain : 搜集目标子域名信息
        -u | --url : 指定目标URL，默认收集所有信息
        --whois : 搜集目标Whois信息

    示例：
        python pigat.py -h：查看帮助信息
        python pigat.py -u teamssix.com ：查看teamssix.com的所有信息
        python pigat.py -u teamssix.com --assert：查看teamssix.com的相关资产信息\033[0m 
        ''')
        sys.exit()
    try:
        for opt,arg in opts:
            if opt in ('-h','--help'):
                print('''\033[1;33;40m
帮助：
    --assert : 搜集目标资产信息
    --cms : 搜集目标CMS信息
    --dns : 搜集目标DNS信息
    --filing : 搜集目标备案信息
    -h | --help ：查看帮助信息
    --ip : 搜集目标IP信息
    --port : 如果两次查询IP结果一致，则扫描该IP端口
    --subdomain : 搜集目标子域名信息
    -u | --url : 指定目标URL，默认收集所有信息
    --whois : 搜集目标Whois信息
                    
示例：
    python pigat.py -h：查看帮助信息
    python pigat.py -u teamssix.com ：查看teamssix.com的所有信息
    python pigat.py -u teamssix.com --assert：查看teamssix.com的相关资产信息
                    \033[0m''')

            elif opt in ('-u','--url'): # 指定url
                url = arg
                deal_url(url)
                if len(argv) == 2:#搜索所有信息
                    for i in threading_list:
                        i.start()
                    for i in threading_list:
                        i.join()
                    port_main()
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
            elif opt in ('--port'): # 搜索IP端口信息
                if 'H1_dnsdumpster' in locals().keys(): #判断H1_dnsdumpster变量有没有被定义，也就是说判断查询IP的两个函数有没有被执行
                    port_main()
                else: # 如果查询IP的两个函数没有被执行就先执行查询IP的函数再查询端口
                    t_ip1.start()
                    t_ip2.start()
                    t_ip1.join()
                    t_ip2.join()
                    port_main()
    except Exception as e:
        print ('\033[1;31;40m[-] 发生异常:{}\033[0m '.format(e))
