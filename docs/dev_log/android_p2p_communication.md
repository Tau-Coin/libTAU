 # Android p2p通信机制

## 1. 发送入口

 - 加好友发送默认消息
 	
    主动加好友: 
           以下几种情况会主动加好友(扫玛(用户的二维码，community社区码)，发送wiring coins的接收方)
    
    收到好友请求: 
    
    		onNewMessage(收到消息会检查sender是否在好友列表中，否则添加并且发送默认消息)
            
            onDiscoveryFriend(收到last_seen信号，信号的发送者如果不在好友列表中，触发加好友行为)
            

- 好友页面手动发送

- Wiring Coins转账交易触发交易消息
		目前只有转账消息的发送，交易状态的改变不发送
        
- 重发消息

## 2. 消息发送过程

       2.1 发送入口触发消息发送，目前不会切分消息，入库后直接发送libTAU模块
       
       2.2 libTAU消息入库后往接收者swarm进行消息的put，put后在回调中进行communication_message_arrived_alert的上报，并通过relay协议告知接收方新消息信号(携带发送新消息的hash)
     
       2.3 android端收到communication_message_arrived_alert会由粉色状态变绿色状态
     
       2.4 消息的接收方收到relay server的relay协议通信，从而知晓有新信息通知，获取到新消息hash后，立马获取新消息内容，获取到消息内容后组织confirm roots，put给发送方的swarm，put回调中通过relay协议发送confirm roots信号(目前是10个消息hash的集合的hash)
       
       2.5 消息的发送方收到relay server的relay协议通信，从而知晓有confirm roots通知，立马获取hash对应的confirm roots集合，获取到confirm roots后，上报communication_confirmation_root_alert，andorid端收到此alert会由绿色变蓝色
       
## 3.重发机制

      12小时内每30分钟，触发12小时内（所有好友列表）中所有未被confirm消息的发送