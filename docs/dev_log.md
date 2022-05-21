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
- 网络切换的过程 

	```
 	网络切换监听方案：在APP中注册监听action为android.net.conn.CONNECTIVITY_CHANGE的BroadcastReceiver广播接收器，
    网络切换会触发一次；当网络变化时，调用ConnectivityManage.getActiveNetworkInfo();获取网络类型Type值，Type值变化
    就直接触发一次libTAU网络的reopen; 
    测试发现当启动VPN时，此时网络类型还是基础网络移动网络或WIFI，此时采取的方案是：getAllNetworks()获取所有的网络，
    如果比当前active网络类型大且是isConnected的网路，直接取其网络类型作为最新网络类型。
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


## Crash分析日志
### Android
1. Quantity为空引发的crash

```
已修复   git log: 1fcbd10155415805207f9886a78437a2e5c8f247
```
### libTAU
<b>libTAU-Blockchain协议升级问题引发的crash</b>

```
协议升级后，数据字段解析存在问题，引发crash
已修复   git log: 710699799d3352978fd5f4d7608459ae98549245
```
解决方法：
```
1) 协议升级后，字段作兼容处理，包括上线测试，先验证旧数据
```

<b>Android UI端和libTAU数据一致性引发的crash</b>

```
一个在android端显示存在的新建链，但是libTAU不存在该链，进而不存在该链对应的交易池，发送交易发生crash
已修复   git log: 322b9e6235b360e37e0ec7a2b93878b67d409a49
```
解决方法：
```
1) android启动libTAU之后，调用获取follow 社区接口，统一两层已follow的chains

2) 接口上考虑兼容，libTAU兼容UI端传入的异常参数，UI端兼容libTAU返回的异常值，详见docs/libTAU_APIS.md
```

 <b>Crash兜底策略</b>
 ```
 在考虑代码正确性、协议升级、数据一致性后如果仍在存在不可预料的crash问题，可利用用户反馈机制来解决。
 
 目前libTAU中集成了breakpad crash dump分析工具，可以抓取一定的未知情况下的crash问题，产生dump文件存在设定的手机路径上。
 
 APK启动后会扫描该路径是否存在新的dump文件，否则认定为之前为非正常退出情况，经用户确认，可以进行异常日志的发送和收集工作，后续服务器可以接收，并进行一定的分析工作，删除已传输国的dump文件。
 ```