### 前言
本来想整个狠的，没想到拉了一坨大的
因为LFI基本上没啥活了，这里就把一些常用的结合在了一起，5个小时写了一坨
本来觉得这应该是个挺牛逼挺好用的工具，然后找了几个题目测了下，好像有点烂，反正魔改魔改也能适配大部分题目了
本项目是面向CTF开发，并无渗透实战功能

### 介绍
集合了以下几种功能

- filter chain 
- 伪协议检测
- 伪协议遍历文件，检测是否有日志文件和pearcmd等文件
- #不使用伪协议直接遍历文件 默认关闭，通常在有过滤的情况下使用
- pearcmd.php利用
- log包含利用
- session文件包含利用

伪协议遍历检测的文件会写入至当前目录下的LFI_file文件夹中，需要手动创建，我懒得再写个功能点了，不创建也不影响运行，能一把梭的就一把梭完了
### 使用
以NSSRound 8 MyDoor作为示例
[https://www.nssctf.cn/problem/3483](https://www.nssctf.cn/problem/3483)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35213294/1695845079177-b6455145-a0d6-4013-8b38-a234beeca832.png#averageHue=%232e2e2d&clientId=u757d9d18-dacd-4&from=paste&height=239&id=u515b65af&originHeight=239&originWidth=701&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=26020&status=done&style=none&taskId=uce3b2a21-480f-4dc7-a302-932df7b6f42&title=&width=701)
装填请求方式 地址 参数 cookie等，直接启动
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35213294/1695845319848-57106c87-c129-4a9c-84df-3bfba9ec4dbc.png#averageHue=%232e2d2d&clientId=u757d9d18-dacd-4&from=paste&height=622&id=u5f932d62&originHeight=622&originWidth=1156&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=81729&status=done&style=none&taskId=u6d959905-fd70-49d8-84a4-c1ac4e09615&title=&width=1156)


### 注意事项

- 本仓库仅用于合法合规用途，严禁用于违法违规用途。
- 本工具中所涉及的漏洞均为网上已公开。
