# coding=utf-8

from Catcher import Catcher

from injector import Injector

from multiprocessing import Process

import os


from Catcher import Catcher
from Configure import capture_interface, injector_interface


'''
def run_proc(name):
    while(1):
        print 1
    print 'Run child process %s (%s)...' % (name, os.getpid())


if __name__ == '__main__':
    print 'Parent process %s.' % os.getpid()
    p = Process(target=run_proc, args=('test',))
    print 'Process will start.'
    p.start()
    p.join()
    print 'Process end.'

'''

catcher = Catcher(capture_interface).packet_sniff()
