import pickle
import os

def get4file(path):
    pkl_file = open(path, 'rb')
    data = pickle.load(pkl_file)
    pkl_file.close()
    return data

def dump2file(path,obj,type=None):
    output = open(path, 'wb')
    pickle.dump(obj, output,type) 
    output.close()
    
def dict2txt(path,obj,act='w',sep=','):
    if not isinstance(obj,dict):
        print "input is not vaild"
        return
    output=open(path,act)
    for k,v in obj.items():
        v=sep.join(v)
        try:
            output.write(k+':'+v+'\n')
        except UnicodeDecodeError:
            k=k.decode('utf8')
            output.write((k+':'+v+'\n').encode('gbk'))
    output.close()
    
def list2txt(path,obj,act='w',sep=','):
    if not isinstance(obj,list):
        print "input is not vaild"
        return    
    output=open(path,act)
    for i in obj:
        try:
            v=sep.join(i)
        except UnicodeDecodeError:
            i=list(i)
            i[1]=i[1].decode('utf8')
            v=(sep.join(i)).encode('gbk')
        output.write(v+'\n')
    output.close()


def getvalue4s(vs,sep=','):
    rs=vs.split(sep)
    if len(rs)==1:
        return rs[0]
    else:
        return tuple(rs)
    
def dict4txt(path):
    if not os.path.isfile(path):
        print "input is not vaild"
        return
    obj={}
    for line in open(path):
        line=line.strip()
        if line:
            try:
                i=line.index(':')
                key=line[:i]
                value=getvalue4s(line[i+1:])
                obj[key]=value
            except Exception:
                print "this is a vaild file"
                exit(1)
    return obj

def list4txt(path):
    if not os.path.isfile(path):
        print "input is not vaild"
        return
    obj=[]
    for line in open(path):
        line=line.strip()
        if line:
            obj.append(getvalue4s(line))
    return obj
"""    
def dump2txt(path,obj):
    f=open(path,'w')
    for i in obj:
        print(i,file=f)
    f.close()
"""