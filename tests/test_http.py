#!/usr/bin/python
#-*- coding:utf-8 -*-
from urllib.request import urlretrieve


def firstLast(webpage):
    f=open(webpage,encoding='utf-8')
    lines=f.readlines()
    f.close()
    print(firstNonBlank(lines))
    lines.reverse()
    print(firstNonBlank(lines))

def download(url='http://www.baidu.com',process=firstLast):
    try:
        retval=urlretrieve(url)[0]
    except IOError:
        retval=None
    if retval:
        process(retval)

if __name__=="__main__":
    download()
