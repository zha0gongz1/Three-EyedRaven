## Three-EyedRaven

中文文档 | [README in English](./README_EN.md)

<hr/>


![three-eyedraven](https://github.com/zha0gongz1/Three-EyedRaven/blob/main/three-eyedraven.jpg)

一款内网探测工具，详细介绍请阅读[此文](https://www.cnblogs.com/zha0gongz1/p/17400520.html)。

## 使用方法：

``` bash
Three-EyedRaven help             #帮助文档

#探测C段主机存活，内置基础端口字典（25个）探测并对结果中存在的可爆破服务进行暴力枚举（内置用户密码字典）
Three-EyedRaven all -H 192.168.233.1/24 

#设定500线程进行all模块探测，禁用爆破模块及web探测（包括401爆破）
Three-EyedRaven all -H 192.168.233.1/24 --nw --nb -t 500

#探测C段存活主机，内置top1000端口字典探测，进行web title识别及401基础认证爆破
Three-EyedRaven detect -H 192.168.233.1/24

#设定300线程探测C段存活主机，内置top1000端口字典探测&&指纹识别，禁用web title识别及401基础认证爆破
Three-EyedRaven detect -H 192.168.233.1/24 --nw -t 300

#探测B段存活主机及其135-139、445、8000-9000端口的开放情况&&端口指纹识别
Three-EyedRaven detect -H 192.168.233.1/16 -P 135-139,445,8000-9000

 #采用内置mysql用户密码字典爆破B段的所有mysql服务，默认200线程
Three-EyedRaven brute -H 192.168.233.1/16 -S mysql

#设定用户、密码字典，爆破主机2222端口的ssh服务
Three-EyedRaven brute -H 192.168.233.11 -S ssh -P 2222 -u 1.txt -p 2.txt

#设定50线程使用密码字典爆破主机ftp服务（默认端口）
Three-EyedRaven brute -H 192.168.233.11 -S ftp -t 50 -p pass.txt   
```

## ToDo: 

- RDP服务认证爆破；

- ~~检测端口，识别SqlServer、Mysql、Redis等服务；~~

## License

The MIT License.
