echo "installing packet-capture program dependencies..."
apt install libpcap-dev -y

echo "making and installing packet-capture program..."
make && make install
ip link set eth2 up
systemctl start packet-capture # 启动流量采集程序
systemctl enable packet-capture.service # 开机自启