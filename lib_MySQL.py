import MySQLdb
import threading

########################################################################
class CMySQL:

    #----------------------------------------------------------------------
    def __init__(self):
        """Constructor"""
        self.host="forstmysql.mysql.rds.aliyuncs.com"
        self.user="forst"
        self.posswd="864804336"
        self.port=3306
        self.db="testdb"
        self.charset='utf8'
        self.conn=None
        self.cur=None
        self.table=None
        self.lock=threading.RLock()
        
    def setParameter(self,pdist):
        if pdist.get('host'):
            self.host=pdist['host']
        if pdist.get('user'):
            self.user=pdist['user']
        if pdist.get('posswd'):
            self.posswd=pdist['posswd']
        if pdist.get('port'):
            self.port=pdist['port']
        if pdist.get('db'):
            self.db=pdist['db']
        if pdist.get('charset'):
            self.db=pdist['charset']    
        if pdist.get('table'):
            self.table=pdist['table']
            
    def connect(self):
        self.conn=MySQLdb.connect(host=self.host,user=self.user,passwd=self.posswd,port=int(self.port),db=self.db,charset=self.charset)
        if self.conn:
            self.cur=self.conn.cursor()
        else:
            print "Connect MySQL fail,check parameter"
            exit(1)
            
    def close(self):
        self.conn.commit()
        self.conn.close()
        self.cur.close()
    
    def test(self):
        if not self.cur:
            print "Connect mysql first"
        self.cur.execute("show databases")
        rs=self.cur.fetchall()
        for r in rs:
            print r
            
    def execute(self,sql,show=False,lock=False):
        if lock:self.lock.acquire()        
        if not self.cur:
            print "Connect mysql first"
        try:
            self.cur.execute(sql)
            rs=self.cur.fetchall()
            if show:
                for r in rs:
                    print r
            if lock:self.lock.release()
            return rs
        except MySQLdb.Error,e:
            print "Mysql Error %d: %s" %(e.args[0],e.args[1])
            if lock:self.lock.release()
            return       
        if lock:self.lock.release()
    def insert(self,vlist,table=None,lock=False):
        if lock:self.lock.acquire()
        if not self.cur:
            print "Connect mysql first"
        try:
            if not table:table=self.table
            if not table:
                print "Please select table"
                if lock:self.lock.release()
                return
            self.cur.execute("insert into %s value(%s)" %(table,"'"+"','".join(vlist)+"'"))
            if lock:
                self.lock.release()
        except MySQLdb.Error,e:
            print "Mysql Error %d: %s" %(e.args[0],e.args[1])
            if lock:self.lock.release()
            return
        if lock:self.lock.release()
        #self.conn.commit()
def getMySQL(pdist=None):
    mysql=CMySQL()
    mysql.setParameter(pdist)
    mysql.connect()
    return mysql    
#mysql=CMySQL()
#mysql.connect()
#mysql.test()
#mysql.close()
        
    
    