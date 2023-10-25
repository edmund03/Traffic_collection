# PacketsCapture
底层基于libpcap实现。本项目实现基于libcap的简单数据包抓取功能。

## 安装Libcap
```
apt install libpcap-dev
```
如果编译找不到`pcap.h`文件，`find / -name "pcap.h"`，将其路径链接放入`/usr/include`目录下


## 配置文件

* `/etc/traffic/default.conf`: 配置log以及pcap存储路径
* `/etc/traffic/category.conf`: app标记信息

## 编译执行
```
make
make install # 安装service服务
```
生成可执行文件packet-capture:
```
./packet-capture # 命令行启动脚本

systemctl start packet-capture # 后台服务启动流量采集功能
```
