# -*- coding: utf-8 -*-
"""
Created on Wed Apr  9 22:31:25 2014

@author: root
"""

#python 2.7
try:
    import httplib2
    import sys
    #import impacket.pcapfile as ppf
    import json
    import os
    import urllib2
    import re
except Exception:
    pass

try:
    from bs4 import *
except Exception:
    from BeautifulSoup import *


cnvd_heads={"Host":"www.cnvd.org.cn",
        "Accept":"text/html, */*",
        "User-Agent":"Mozilla/5.0 (Windows NT 5.1; rv:23.0) Gecko/20100101 Firefox/23.0",
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
        "Connection":"keep-alive",
        "Cache-Control":"no-cache"}
bdfanyi_heads={"Host":"fanyi.baidu.com",
               "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0",
               "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
               "Connection":"keep-alive",
               "Cache-Control":"no-cache"}

#wcnvd=httplib2.Http()
#sf=httplib2.Http()
#wcve=httplib2.Http()
#wcnnvd=httplib2.Http()

class grule:
    def __init__(self):
        self.data=False
        self.protocol="tcp"
        self.action="alert"
        self.direct="->"
        self.rev="1"
        self.cve=""
        self.bid=""
        self.cnvd=""
        self.ip1="any"
        self.ip2="any"
        self.port1=""
        self.port2=""
        self.msg=""
        self.ename=""
        self.solve=""
        self.version=""
        self.cdesc=""
        self.edesc=""
        self.body=""
        self.flow="to_server"
        self.sid=""
        self.see=""
    def setdata(self,dt):
        self.protocol=dt['protocol']
        self.action=dt['action']
        self.direct=dt['direct']
        self.rev=dt['rev']
        self.cve=dt['cve']
        self.bid=dt['bid']
        self.cnvd=dt['cnvd']
        self.ip1=dt['ip1']
        self.ip2=dt['ip2']
        self.port1=dt['port1']
        self.port2=dt['port2']
        self.msg=dt['msg']
        self.ename=dt['ename']
        self.solve=dt['solve']
        self.version=dt['version']
        self.cdesc=dt['cdesc']
        self.edesc=dt['edesc']
        self.body=dt['body']
        self.flow=dt['flow']
        self.sid=dt['sid']
        self.see=dt['see']
        self.data=True
    def getrule(self):
        rule=self.action+' '+self.protocol+' '+self.ip1+' '+self.port1+' '+\
            self.direct+' '+self.ip2+' '+self.port2+' (msg:\"'+self.msg+'\"; '
        if self.flow:
            rule+='flow:'+self.flow+',established; '
        rule+=self.body
        if self.cve:
            rule+=' reference:cve,'+self.cve+';'
        if self.bid:
            rule+=' reference:bid,'+self.bid+';'
        rule+=" sid:"+self.sid+'; rev:'+self.rev+';)'
        self.rule=rule
        return rule
    def getdatabody(self):
        data="@==========================================\n"
        data+="action:"+self.action+'\n'
        data+="protocol:"+self.protocol+"\n"
        data+="ip1:"+self.ip1+"\n"
        data+="port1:"+self.port1+"\n"
        data+="direct:"+self.direct+"\n"
        data+="ip2:"+self.ip2+"\n"
        data+="port2:"+self.port2+"\n"
        data+="msg:"+self.msg+"\n"
        data+="flow:"+self.flow+"\n"
        data+="body:"+self.body+"\n"
        data+="cve:"+self.cve+"\n"
        data+="cnvd:"+self.cnvd+"\n"
        data+="bid:"+self.bid+"\n"
        data+="sid:"+self.sid+"\n"
        data+="rev:"+self.rev+"\n"
        data+="see:"+self.see+"\n"
        data+="solve:"+self.solve+"\n"
        data+="ename:"+self.ename+"\n"
        data+="version:"+self.version+"\n"
        data+="cdesc:"+self.cdesc+"\n"
        data+="edesc:"+self.edesc+"\n"
        return data
    def getdatadict(self):
        dt={"protocol":self.protocol ,"action":self.action ,\
            "direct":self.direct ,"rev":self.rev,"cve":self.cve,\
            "bid":self.bid ,"cnvd":self.cnvd ,"ip1":self.ip1 ,\
            "ip2":self.ip2 ,"port1":self.port1 ,"port2":self.port2,\
            "msg":self.msg ,"ename":self.ename ,"solve":self.solve ,\
            "version":self.version ,"cdesc":self.cdesc ,"edesc":self.edesc ,\
            "body":self.body ,"flow":self.flow ,"sid":self.sid ,"see":self.see}
        return dt
    def getauto(self):
        if self.cve and ((not self.bid) or (not self.edesc) or (not self.ename)):
            bid,edesc_cve=getdesc4cve(self.cve)
            if not self.bid:
                self.bid=bid
            if not self.edesc:
                self.edesc=edesc_cve
            if self.bid and (not self.ename):
                ename,edesc_bid=getdesc4bid(self.bid)
                self.ename=ename
        if self.bid and ((not self.edesc) or (not self.ename) or (not self.version)):
            ename,edesc_bid=getdesc4bid(self.bid)
            if not self.ename:
                self.ename=ename
            if not self.edesc:
                self.edesc=edesc_bid
            if not self.version:
                self.version=getversion4bid(self.bid)[1]
        if (not self.cnvd) and self.cve:
            cname,cnvd=getCNVD(self.cve)
            if not self.cnvd:
                self.cnvd=cnvd
            if not self.msg:
                self.msg=cname
        if  self.cnvd and (not self.cdesc):
            cname,cdesc=getdesc4cnvd(self.cnvd)
            if not self.cdesc:
                self.cdesc=cdesc
            if not self.msg:
                self.msg=cname




def gethttp4urllib(url):
    rs=urllib2.urlopen(url)
    if rs and rs.getcode()==200:
        return rs.read()

def getversion4bid(bid,multi=0):
    url="http://www.securityfocus.com/bid/"+bid
    try:
        sf=httplib2.Http()
        rp,con=sf.request(url)
        #con=gethttpdata(url)
        soup=BeautifulSoup(con)
        rs=soup.find('div',id='vulnerability')
        ename=rs('span')[0].contents[0]
        rs=soup.find('table',border="0",cellspacing="0",cellpadding="4")
        rs=rs.findAll('tr')
        version=rs[8]('td')[1].contents[0]
        return ename,clearstr(version)
    except Exception:
        return "",""

def getCNVD(cve):
    wcnvd=httplib2.Http()
    body="&condition=1&causeIdStr=&threadIdStr=&serverityIdStr=&positionIdStr=&keyword=&keywordFlag=0&cnvdId=&cnvdIdFlag=0&baseinfoBeanbeginTime=&baseinfoBeanendTime=&baseinfoBeanFlag=0&refenceInfo="+cve+"&referenceScope=1&manufacturerId=-1&categoryId=-1&editionId=-1"
    url="http://www.cnvd.org.cn/flaw/listResult"
    try:
        rp,rs=wcnvd.request(url,method="POST",headers=cnvd_heads,body=body)
        soup=BeautifulSoup(rs)
        if soup('a'):
            cnvd=soup('a')[0]['href'][16:]
            cname=soup('a')[0]['title']
            return cname.encode('utf8'),cnvd.encode('utf8')
        else:
            return "",""
    except Exception:
        return "",""

def opencnvdurl(http,url):
    h,b=http.request(url,headers=cnvd_heads)
    if h['status']=='200':
        return b

def searchdesc4soup(ss):
    for s in ss:
        if s('td')[0].contents[0]==u'漏洞描述':
            return s('td')[1].contents
    return None

def getdesc4cnvd(cnvd,code='utf8',vid=False,rhttp=None):
    url="http://www.cnvd.org.cn/flaw/show/CNVD-"+cnvd
    try:
        if not rhttp:
            rhttp=httplib2.Http()
        rp,con=rhttp.request(url,headers=cnvd_heads)
        soup=BeautifulSoup(con)
        cname=soup('h1')[0].contents[0]
        rs=soup.find('table',{'class':"gg_detail"})
        rs=rs.find('tbody')
        rs=rs.findAll('tr')
        if vid:
            cve,bid=getvidforsoup(rs,code)
        desc=""
        rs=searchdesc4soup(rs)
        for i in rs:
            if type(i)==type(cname):
                desc+=i
        if vid:
            return cve,bid,cname.encode(code),clearstr(desc).encode(code)
        return cname.encode(code),clearstr(desc).encode(code)
    except Exception:
        return "",""

def getvidforsoup(soups,code='utf8'):
    bid='NULL'
    cve='NULL'
    for soup in soups:
        if soup.td.contents[0]=='BUGTRAQ ID':
            v=soup('td')[1].a.contents[0].strip()
            if v:bid=v
        elif soup.td.contents[0]=='CVE ID':
            v=soup('td')[1].a.contents[0].strip()
            if v:cve=v
    if cve!='NULL':
        cve=cve[4:]
    return cve.strip().encode(code),bid.strip().encode(code)

def getpacket4file(fname,func):
    f=ppf.PcapFile(fname)
    rs=f.read()
    while rs:
        func(rs.fields)
        rs=f.read()
    f.close()

def ishttprequest(pkt):
    rlist=('GET','POST','PUT','DELETE','OPTIONS','PATCH','PROPFIND','PROPATCH',\
           'MKCOL','COPY','MOVE','LOCK','UNLOCK','TRACE','HEAD')
    data=pkt['data']
    for i in rlist:
        s=data.find(i,54,100)
        p=0
        if s>0:
            m=data.find('\r\n',s)
            if i=="POST":
                p=data.find("\r\n\r\n",m)
            if m>0:
                return s,m,p+4
            else:
                return s,200+s,p+4
    return None

def gethttp4file(fname,func):
    f=ppf.PcapFile(fname)
    rs=f.read()
    while rs:
        pi=ishttprequest(rs)
        if pi:
            func(rs.fields,pi)
        rs=f.read()
    f.close()

def findspit(s,subs,start=0,fs=' ;'):
    while 1:
        seq=s.find(subs,start)
        if seq>start and (s[seq-1] in fs):
            return seq
        if seq ==-1:
            return -1
        start=seq+1

def getidmsg4rule(line):
    s=line.find("msg:");
    f=line.find("\"",s+5)
    msg=line[s+5:f]
    s1=findspit(line,'sid:',f)
    s2=findspit(line,'tid:',f)
    s=max(s1,s2)
    f=line.find(";",s+4)
    sid=line[s+4:f]
    try:
        if int(sid)<100:
            print sid
    except Exception:
        print sid
        pass
    return sid,msg


def getdata4line(line,flag=0): #1 return rule 2 filter flowbits:noalert
    if line[0]=="#":
        if line[1:7]=='TOPXXX' or line[1:7]=='TOPXXX':
            pass
        else:
            return
    if flag==2 and line.find("flowbits:noalert;")>0:
        return
    s=line.find("msg:");
    f=line.find("\"",s+5)
    msg=line[s+5:f]
    s1=findspit(line,"sid:",f)
    s2=findspit(line,"tid:",f)
    s=max(s1,s2)
    f=line.find(";",s+4)
    sid=line[s+4:f]
    try:
        if int(sid)<100:
            print sid
    except Exception:
        print sid
        pass
    if flag==1:
        return sid,msg,line
    return sid,msg

def getinfo4rule(path,flag=0):
    grule={}
    try:
        f=open(path,'r')
        ls=0
        for i in f:
            ls+=1
            i=i.strip()
            if len(i)==0:
                continue
            if i[:7]=='include':
                grule.update(getinfo4rule(i[8:].strip()))
                continue
            rp=getdata4line(i,flag)
            if rp:
                if flag==1:
                    grule[rp[0]]=[rp[1],rp[2]]
                else:
                    grule[rp[0]]=[rp[1]]
            else:
                print ls,i
    except Exception:
        print "have error in getinfo4rule"
    return grule

def transen2zh(en=None,encode='utf-8'):
    url="http://fanyi.baidu.com/v2transapi"
    post={"from":"en","query":"this is a test","to":"zh","transtype":"trans"}
    try:
        if en:
            post['query']=en
        post=httplib2.urllib.urlencode(post)
        bd=httplib2.Http()
        rp,con=bd.request(url,method="POST",body=post,headers=bdfanyi_heads)
        js=json.loads(con)
        rs=js['trans_result']['data'][0]['dst']
        if encode=='utf-8':
            return rs.encode('utf-8')
        else:
            return rs.encode(encode)
    except Exception:
        return None

def getdesc4bid(bid,rhttp=None):
    url="http://www.securityfocus.com/bid/"+bid+"/discuss"
    try:
        if not rhttp:
            rhttp=httplib2.Http()
        rp,con=rhttp.request(url)
        soup=BeautifulSoup(con)
        rs=soup.find('div',id='vulnerability')
        ename=rs('span')[0].contents[0]
        edesc=""
        for i in rs.contents:
            if type(ename)==type(i):
                edesc+=i
        edesc=clearstr(edesc)
        return ename,edesc
    except Exception:
        return "",""

def clearstr(ss):
    ss=ss.strip()
    return ss.replace('\r','').replace('\n','').replace('\t','')

def getbid4link(link):
    l=len(link)-1
    while l>0:
        if link[l]=='/' or link[l]=='\\':
            return link[l+1:]
        l-=1
    return ""

def getdesc4cve(cve,code='utf8',rhttp=None):
    url="http://www.cve.mitre.org/cgi-bin/cvename.cgi?name="+cve
    try:
        if not rhttp:
            rhttp=httplib2.Http()
        rp,con=rhttp.request(url)
        soup=BeautifulSoup(con)
        rs=soup.find('table',width="100%",border="0",cellspacing="0",cellpadding="0")
        edesc=rs('tr')[3]('td')[0].contents[0]
        edesc=clearstr(edesc)
        lt=rs('tr')[6].findAll('a')
        bid=''
        for i in lt:
            if i['href'].find("www.securityfocus.com/bid/")>=0:
                bid=getbid4link(i['href'])
                break
        return bid.encode(code),edesc.encode(code)
    except Exception:
        return "",""

def getdata4colon(line):
    lt=line.split(':',1)
    if len(lt)==2:
        return lt
    else:
        return None

def getinfo4grule(path):
    if not os.path.isfile(path):
        print path,"is not a file or not exist"
        return
    f=open(path)
    grule=[]
    temp={}
    for line in f:
        line=line.strip()
        if line[0]=="@" and temp:
            grule.append(temp)
            temp={}
            continue
        rs=getdata4colon(line)
        if rs:
            temp[rs[0]]=rs[1]
    return grule

def gettid4file(path):
    tids=[]
    f=open(path)
    for line in f:
        tid=line.strip()
        if tid.isdigit():
            tids.append(tid)
    f.close()
    return tids

def istidrules(path):
    f=open(path)
    for line in f:
        line=line.strip()
        if line[0]=='#':
            continue
        f.close()
        if line.find('tid:')>0:
            return 1
        else:
            return 0

def searchtidrules(path):
    lts=os.listdir(path)
    for lt in lts:
        if os.path.splitext(lt)[1]=='.rules':
            if istidrules(path+'/'+lt):
                return path+'/'+lt
    return None

def gettid4dir(path):
    lts=os.listdir(path)
    tids=[]
    for lt in lts:
        if lt[-5:]=='.pcap':
            tids.append(lt[:-5])
    return tids

def getCNNVD(cve):
    '''
    soup=BeautifulSoup(body)
    if len(soup.find('div',{"class":"dispage"}).contents[0])<10:
        return None
    '''
    wcnnvd=httplib2.Http()
    head,body=wcnnvd.request("http://www.cnnvd.org.cn/vulnerability/index/cnnvdid2/CVE-"+cve)
    index=body.find('>CNNVD')
    if index<=0:
        return None
    return body[index+7:body.find('<',index)]

def parserule(line,ln=0):
    rhead=re.compile(r"^(#(TOPXXX|TOPXXX) *)?(alert|drop|log|pass|activate) +(tcp|udp|ip|icmp) +(any|[!\d\.]+|\x24.+) +(any|[!\[\]:,\d]+|\x24.+) +(->|<-|<>) +(any|[!\d\.]+|\x24.+) +(any|[!\[\]:,\d]+|\x24.+)$",re.I)
    line=line.strip()
    if len(line)<3:
        return None
    index_h=line.find('(msg:')
    if index_h<=0:
        if ln>0:
            print "Error rule in %d" %ln
        return None
    if line[-2:]!=';)':
        if ln>0:
            print("Error rule in %d" %ln)
        return
    head=line[:index_h].strip()
    body=line[index_h:].strip()
    rs={}
    m=rhead.match(head)
    if not m:
        if ln>0:
            print("Error rule in %d" %ln)
        return
    rs['head']=m.groups()
    rs['body']=[]
    i=1
    cur=1
    while i<len(body):
        if body[i]==';':
            key=body[cur:i].strip()
            #print key
            i=i+1
            cur=i
            rs['body'].append(key)
            continue

        if body[i]==':':
            key=body[cur:i].strip()
            j=i+1
            while 1:
                j=body.find(';',j)
                if j>0 and body[j-1]=='\\':
                    j+=1
                    continue
                break
            value=body[i+1:j].strip()
            #print key,value
            rs['body'].append((key,value))
            i=j+1
            cur=i
            continue
        i+=1
    return rs

def mystrip(s):
    if s[0]==s[-1]=='"' or s[0]==s[-1]=="'":
        return s[1:-1].strip()
    else:
        return s.strip()

def getostype():
    import platform
    k=platform.system()
    if k=="Windows":
        return 0
    elif k=="Linux":
        return 1
    else:
        return -1
