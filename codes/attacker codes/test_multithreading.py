from threading import Thread
from Queue import Queue
import time
start = time.time()
def worker(q):
   while True:
      print "This is thread",q.get()
      q.task_done()
q =Queue()

for i in range(1,2):
   work_er = Thread(target=worker,args=(q,))
   work_er.setDaemon(True)
   work_er.start()
   
for i in range(1,5):
   q.put(i)
q.join()
print "Total time taken --",(time.time()-start)
