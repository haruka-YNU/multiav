# -*- coding: utf-8 -*-

from pprint import pprint
import time
import os
import sys
from pymongo import MongoClient
from multiav.core import CMultiAV, AV_SPEED_ALL

client = MongoClient('mongodb://192.168.10.101:27017/email')
db = client.email
collection_name = sys.argv[1].split('/')[3] + '.' + sys.argv[1].split('/')[4]
collection = db[collection_name]
floder_list = []

def call_multiav(scan_path):
    multi_av = CMultiAV('./config.cfg')
    ret = multi_av.multi_scan(scan_path, AV_SPEED_ALL)
    AV_result_list = []
    for file in os.listdir(scan_path):
        for AV_engin, AV_result in ret.items():
            for file_path, malware in AV_result.items():
                AV_result_list.append('%s : %s : %s' % (file, AV_engin, malware))
                break
    return AV_result_list

def loop(root):
    for path in os.listdir(root):
        if os.path.isfile(os.path.join(root, path)):
            if root not in floder_list:
                floder_list.append(root)
        else:
            loop(os.path.join(root, path))
    return floder_list

def scan(floder_list):
    fmt = '\033[0;3{}m{}\033[0m'.format
    count = 1
    total = len(floder_list)
    for file_dir in floder_list:
        print '(%d/%d)%s:' % (count, total, file_dir)
        t0 = time.time()
        AV_result_list = call_multiav(file_dir)
        if len(AV_result_list) != 0:
            collection.update({"FileName":file_dir.split('/')[-1]},
                              {"$set":{"IsMalicious":True,"AVInfo":AV_result_list}})
            for r in AV_result_list:
                print fmt(1, '             '+ r)
        else:
            print fmt(2, '             Clear')
        cost = time.time() - t0
        print "             %.3fs taken" % (time.time() - t0)
        count += 1
    return None

if __name__ == "__main__":
    floder_list = loop(sys.argv[1])
    scan(floder_list)