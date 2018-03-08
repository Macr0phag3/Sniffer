```
 __  __                  ___        _                 _____       
|  \/  | __ _  ___ _ __ / _ \ _ __ | |__   __ _  __ _|___ /  Tr0y 
| |\/| |/ _` |/ __| '__| | | | '_ \| '_ \ / _` |/ _` | |_ \       
| |  | | (_| | (__| |  | |_| | |_) | | | | (_| | (_| |___) | v2.0 
|_|  |_|\__,_|\___|_|   \___/| .__/|_| |_|\__,_|\__, |____/       
                             |_|                |___/      Sniffer
```
# 中文

## 介绍

有一天我在无意中发现，学校的WLAN是开放的。

也就是说，身边充满了Cookie与明文密码，我们只需要伸伸手，便可以拿到。

然后又发现了add在freebuf发的[一篇文章](http://www.freebuf.com/articles/network/129721.html)，进而对写一个嗅探器愈发有兴趣，于是就有了这个工具。

总之一句话，这个工具是用来嗅探开放WLAN下的数据包，具体嗅探的是含Cookie或者Method为Post的数据包。

## 食用方法

嗅探器是一个类，有以下参数：

1. iface：可选参数；嗅探使用的原始无线网卡的名字，若不填则代码会自动指定无线网卡
2. newiface：可选参数；默认值为‘mon0’；由于嗅探需要开启无线网卡的监听模式（monitor），这个是将原始无线网卡改为监听模式后的名字（改为监听模式并非直接改原无线网卡，而是生成一个处于监控模式的虚拟无线网卡）；这个虚拟的无线网卡在嗅探器停止后会自动删除。
3. filename：可选参数；默认为空；嗅探器可以实时嗅探，也可以解析本地的pcap包，这个参数就是本地pcaps包的名字，注意一定要放在Pcaps目录里；只需填写文件名；
4. outputmode：可选参数；默认为1；嗅探器一旦发现Cookie或者Post的包，就会进行对应的输出，若不想看见实时输出，则置0，否则置1。
5. savingPkt：可选参数；默认为1；嗅探器发现符合filter的数据时，会对输出的结果进行保存；若不想保存这些结果，置0；默认保存在Pkts下
6. savingPcap：可选参数；默认为0；嗅探器可以保存符合filter的原始数据包；1为保存；0为不保存；默认保存在Pcaps下
7. filtermode：可选参数；默认为空；与scapy的过滤语法一致，对数据包进行过滤；代码在后面默认过滤自己的ip，以及只嗅探web相关的包；
8. iHost：可选参数；默认为空列表；在这里面包含的host，在停止嗅探后会高亮显示。

举个调用的例子：

```
Sniffer(savingPkt = 1, savingPcap = 1)
```

运行方式：`sudo python sniffer.py`

运行截图：

![example](https://github.com/Macr0phag3/Sniffer/blob/master/PicForReadme/example.png)

捕获cookie时的截图：

![outputmode](https://github.com/Macr0phag3/Sniffer/blob/master/PicForReadme/outputmode.png)

停止时（Ctrl+c）的截图：

![stop](https://github.com/Macr0phag3/Sniffer/blob/master/PicForReadme/stop.png)

![stop](https://github.com/Macr0phag3/Sniffer/blob/master/PicForReadme/stop1.png)

## 注意

1. 需要的库：

   scapy

   scapy_http

   termcolor

   这些库可以手动安装。

   嗅探器在启动的时候也会自动检查环境并进行修复。

   ​

2. 配置：

   Ubuntu（其他Linux应该也可以）

   `pip`，`iw`，`iwconfig`，`ifconfig` 需可用

   以管理员权限运行

   ​

3. Python版本

   2.x


## 后续更新

1. v2.0简化了实现，但是貌似还算不够简洁（逃
2. 代码中有插件功能，用意是捕获到指定的数据包时，可以由插件来完成后续的工作。例如，我校的校园网帐号密码可以用cookie拿到，那么这个功能就可以写成插件。弄插件的另一个目的是分离核心代码与其他代码。
3. 编码问题出现的比较多，会想办法更好地进行捕捉与处理。

## 一些话

目前写的比较粗糙，后续有时间会改进。但是功能是比较完善的。

欢迎评论以及修改

（仅限学术交流，用于非法用途概不负责）

原理会先写在[我的博客](www.tr0y.wang)上，有空会搬到Gayhub来

 # English

Wating...

