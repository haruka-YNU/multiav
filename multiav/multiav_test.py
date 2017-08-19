# -*- coding: utf-8 -*-

from pprint import pprint
import time
import pickle
import os
from core import CMultiAV, AV_SPEED_ALL

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

def scan(path):
    fmt = '\033[0;3{}m{}\033[0m'.format
    count = 1
    mal_list = []
    total_cost = 0.0
    total = len(os.listdir(path))
    for file_dir in os.listdir(path):
        print '(%d/%d)%s :' % (count, total, file_dir)
        scan_path = os.path.join(path, file_dir)
        t0 = time.time()
        AV_result_list = call_multiav(scan_path)
        cost = time.time() - t0
        if len(AV_result_list) != 0:
            mal_list.append(count)
            for r in AV_result_list:
                print fmt(1, '             '+ r)
        else:
             print fmt(2, '             Clear')
        print "             %.3fs taken" % (time.time() - t0)
        count += 1
        total_cost += cost
    ava_cost = total_cost/2729
    with open('../result/McAfee.txt', 'w') as f:
        pickle.dump(mal_list, f)
    return ava_cost

if __name__ == "__main__":
    re = scan('/root/git/bulk_files/')
    print re