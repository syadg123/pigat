# Pigat：一款被动信息收集聚合工具
## 拒绝白嫖，从我做起，求个star★呀(～￣▽￣)～
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
```
![](https://teamssix.oss-cn-hangzhou.aliyuncs.com/pigat1.png)
2.指定url进行信息获取
```
# python pigat.py -u teamssix.com
```
![](https://teamssix.oss-cn-hangzhou.aliyuncs.com/pigat2.png)
3.指定url进行单项信息获取
```
# python pigat.py -u teamssix.com --cms
```
![](https://teamssix.oss-cn-hangzhou.aliyuncs.com/Snipaste_2019-11-27_14-50-01.png)
4.指定url进行多项信息获取
```
# python pigat.py -u teamssix.com --ip --cms
```
![](https://teamssix.oss-cn-hangzhou.aliyuncs.com/pigat5.png)

### 写在最后
因为我没有太多的开发经验，因此该工具难免存在有问题以及不恰当的地方，希望各位大佬在使用的过程中碰到问题能够多多反馈。

开发不易，还望大佬们走过路过顺手给个star，小弟将不胜感激。

PS：该工具将会持续更新
