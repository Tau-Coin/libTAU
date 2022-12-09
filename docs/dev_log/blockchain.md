1. 新版交易逻辑设计

   p2p msgs消息

       1) put机制: ui端来控制，ui编辑完触发发送；24小时内每30分钟，触发最近所有未被confirm消息的发送；

          发送方communication模块收到发送信号: 立马put消息，put成功后(大于0的server收到消息), 在put接口回调中上报communication_message_arrived_alert，ui端收到此alert会由粉色变绿色，并发送信号（相应的频道内携带消息指针)，此信号只发送一遍；
          
       2) forward机制: 无；
      
       3) get机制: 
          接收方目前利用keep协议来和relay server通信，以此来知晓有新信息通知，获取到新消息hash后，立马获取新消息内容，获取到消息内容后通知发送方confirm roots(目前是10个消息hash的集合)
       
          发送方也是利用keep协议(2s频率)来和relay server通信，以此来知晓有confirm roots通知，立马获取confirm roots集合，获取到confirm roots后，上报communication_confirmation_root_alert，ui端收到此alert会由绿色变蓝色；

   note tx中保留链式结构(链接发送者发送的前1个消息)， 无nonce无tx fee

       1) put机制: ui端来控制: 编辑完触发发送；12小时内每30分钟，触发最近的10笔note tx发送(包括社区其他人的Note交易)；

          blockchain收到ui发送任务: 会执行put，并修改探索信号内容（携带note tx指针），面向访问列表集合发送10次，每次间隔30s；

          blockchain本地交易池一把key只会保留3笔note tx；
   	  
       2) forward机制: 参考探索信号发送策略；
      
       3) get机制: 
          访问列表中的peer利用keep协议感知特定chain的信号变化，当感知到是note tx信号变化后立即执行get，并会根据链式hash get 10笔note tx(需要设计数据库来记录已获得的note tx);

   news note tx中无链式结构, 有nonce有tx fee

       1) put机制：ui端控制, 编辑完触发发送(同时会触发最近一笔nonce交易的重发); 12小时内每30分钟，触发最近所有未上链的news note tx的发送；

        blockchain收到发送任务: 会执行put，并修改探索信号内容（携带note new tx指针），面向访问列表集合发送10次，每次间隔30s；

          本地交易池一把key只会保留3笔交易（这个和所有未上链的news note tx笔数有一点冲突）；
   	  
       2) forward机制: 参考探索信号发送策略；
      
       3) get机制: 
        访问列表中的peer利用keep协议感知特定chain的信号变化，当感知到是note news tx信号变化后立即执行get，非链式结构，只get信号指针指向的tx

   payment转账交易,有nonce有tx fee

       1) put机制: ui端发送控制, 编辑完触发发送(触发最近一笔nonce交易的重发)，当前nonce不一定会被发送(否则交易费策略会冲掉小nonce交易)

         链状态的修改会触发未上链的一笔（最近nonce）tx的发送，因为new note tx也有nonce

   	  当触发wiring coins tx交易发送时，同时触发p2p msgs，通知接收方转账行为, 接收方收到该交易消息后需要更新交易列表数据库, 显示Pending状态；

          blockchain收到发送任务: 执行put，并修改探索信号内容（携带wiring coins tx指针）面向访问列表集合(会额外加入接收者进入集合)发送10次，每次间隔30s；

   	  blockchain本地交易池一把key只会保留1笔交易（nonce是否合法；nonce如果都合法，取交易费大者）；

   	  communication收到发送wiring通知信号: 直接执行点对点消息发送，发送过程参考第一部分；
   	  
       2) forward机制: 参考探索信号发送策略； 
      
       3) get机制: 
       
       访问列表中的peer利用keep协议感知特定chain的信号变化，当感知到有wiring coins tx信号变化后，查看交易费是否大于当前链中的交易，如果大于则会记录在m_best_tx_info中，后续 5分钟周期性执行get(get积累5分钟中所有转账交易信号里面最大的那一笔转账)，没有链式结构，只会get选中的这笔交易

    block

       1) put机制: 当矿工挖出新的head block时，会put整条链，包括所有block和state，然后向接收者集合发送信号（携带head block指针）10次，每次间隔30s
		  
       2) forward机制: 参考探索信号发送策略；
	   
       3) get机制: 
         访问列表中的peer利用keep协议感知特定chain的信号变化，当感知到有new head block信号变化后，查看难度值是否大于当前累积的难度值，如果大于则会记录在m_head_block_info中，后续 5分钟周期性执行get(get积累的5分钟内累积的最难head block)，有链式结构，get选中的区块以及之前的区块

概念补充：

1. 探索信号发送策略

	探索信号有自己的频率（根据策略计算得到），每次频率到了必定会发一个探索信号；
 	探索信号携带什么信息是有概率的；

		1) 假如自己存在发送行为（消息、交易），就有10个间隔30s任务，
		   如果这个10个任务没发完，会优先看一下间隔时间是否到了，间隔到了就会发这个；
							 
		2) 如果没到时间或者10个都发完了，会概率性选择携带head block或者交易；

			a) 如果选择head block，就会携带打听到的最难的head block；

			b) 如果选择的是交易，目前区分到3种交易；
              
                当探索信号转发news note tx交易时，随机转发交易池时间戳排名前40的news note交易指针；
				note和news交易在最近40笔中随机选择1笔，修改探索信号内容（携带交易指针），面向接收者集合发送1次，不执行put；
                
                当探索信号转发news note tx交易时，随机转发交易池时间戳排名前40的news note交易指针；
				note和news交易在最近40笔中随机选择1笔，修改探索信号内容（携带交易指针），面向接收者集合发送1次，不执行put；
			
                当探索信号转发payment交易时，转发交易池验证过的交易费最大的交易指针；面向访问列表集合（加入receiver）发送1次，不执行put；

2. 访问列表

3. keep信号频率
       当前频率是2s
