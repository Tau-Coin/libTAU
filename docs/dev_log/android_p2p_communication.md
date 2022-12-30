1. 新版交易逻辑设计

   p2p msgs消息

       1) put机制: ui端来控制，ui编辑完触发发送；24小时内每30分钟，触发最近所有未被confirm消息的发送；

          发送方communication模块收到发送信号: 立马put消息，put成功后(大于0的server收到消息), 在put接口回调中上报communication_message_arrived_alert，ui端收到此alert会由粉色变绿色，并发送信号（相应的频道内携带消息指针)，此信号只发送一遍；
          
       2) forward机制: 无；
      
       3) get机制: 
          接收方目前利用keep协议来和relay server通信，以此来知晓有新信息通知，获取到新消息hash后，立马获取新消息内容，获取到消息内容后通知发送方confirm roots(目前是10个消息hash的集合)
       
          发送方也是利用keep协议(2s频率)来和relay server通信，以此来知晓有confirm roots通知，立马获取confirm roots集合，获取到confirm roots后，上报communication_confirmation_root_alert，ui端收到此alert会由绿色变蓝色；
