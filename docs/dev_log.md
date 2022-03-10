# libTAU_0.0

## Session IMPL

### 1. Reopen机制
- 将ip_notifier由默认的true改为false状态
    ```
	1. ip_notifier对于服务器节点而言，通知并不准确，存在ip不发生改变也会触发ip_notifier
	2. ip_notifier对于移动设备而言，有些型号或者网络的切换不会触发ip_notifier
	3. 综上，目前ip_notifier的通知并不靠谱，V0.0做如下改动，默认为关闭状态；移动端应用层来通知网络切换，触发reopen机制
    ```
- 可用ip interface的监听
	```
	1. android目前的获取有如下问题：存在获取不到active ip interface的情况；在vpn网络情况下，获取的ip interface是错误的情况；
	2. libTAU目前是linux平台，基于netlink获取可用ip interface的过程目前看是靠谱的，只不过要设定策略
	3. 通过netlink获取可用ip interface，利用Android应用端来触发reopen机制

	```
- reopen的触发机制
  ```
  1. 目前完全由ui端上层来触发，主要分为网络切换和兜底机制；
  2. 网络切换的过程：Android端的网络有不同的类型：移动网络、WIFI、VPN网络等，每种网络对应了不同的网络类型；
  3. 兜底机制，网络中可用节点数为0，会触发reopen，这个是检测断网的最后机制，在已连接的peers很多情况下，这个机制有很大的滞后性；
  ```
    
### 2.Port选取
- port和id建立映射关系；
- 在已建立映射关系的基础上，保留目前和libTorrent一致的策略，绑定不成功后进行port+1的尝试；

### 待解决问题
- reopen listen socket时，可用节点的存取
	```
    1.目前的过程是两步，第一步连接Bootstrap节点，第二步连接Relay节点；
    2.需要解决可用节点（Relay、Peers等）的存储；
    3.解决完存取节点的工作，需要进一步交流第一批节点的链接问题，以此和libTAU当前网络状态挂钩；
    ```
    
## Android UI

[Android-dev-log](https://github.com/Tau-Coin/libTAU/blob/master/docs/dev_log/android.md)
## DHT Network
[DHT-dev-log](https://github.com/Tau-Coin/libTAU/blob/master/docs/dev_log/DHT.md)
## Communication
[Module-communication-dev-log](https://github.com/Tau-Coin/libTAU/blob/master/docs/dev_log/communication.md)
## Blockchain
[Module-blockchain-dev-log](https://github.com/Tau-Coin/libTAU/blob/master/docs/dev_log/blockchain.md)

