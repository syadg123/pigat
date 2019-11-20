# Pigat：一款被动信息收集聚合工具
##求star!!! 拒绝白嫖，从我做起
### 前言
Pigat即Passive Intelligence Gathering Aggregation Tool，翻译过来就是被动信息收集聚合工具，既然叫聚合工具，也就是说该工具将多款被动信息收集工具结合在了一起，进而提高了平时信息收集的效率。
### 功能概述
目前该工具具备8个功能，原该工具具备7个功能，分别为收集目标的资产信息、CMS信息、DNS信息、备案信息、IP地址、子域名信息、whois信息，现加入第8个功能：如果在程序中两次IP查询目标URL的结果一致，那么查询该IP的端口。
### 使用方法：
1. 安装所需要的模块：requests,BeautifulSoup4，也可以使用`pip install -r requirements.txt`进行安装
1. `-h`查看帮助,`-u`指定url，其他更多操作都在下面示例帮助里
### 下载地址：
[点击进入下载页面](https://github.com/teamssix/pigat/releases)
### 示例：
1.查看帮助信息

```
# python pigat.py -h

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
```
2.指定url进行信息获取
```
# python pigat.py -u teamssix.com
```
3.指定url进行单项信息获取
```
# python pigat.py -u teamssix.com --cms
```
4.指定url进行多项信息获取
```
# python pigat.py -u teamssix.com --ip --cms
```
### 写在最后
因为我没有太多的开发经验，因此该工具难免存在有问题以及不恰当的地方，希望各位大佬在使用的过程中碰到问题能够多多反馈。

开发不易，还望大佬们走过路过顺手给个star，小弟将不胜感激。

PS：该工具将会持续更新
