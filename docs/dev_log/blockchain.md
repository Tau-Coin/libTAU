1. 新版交易逻辑设计

   p2p msgs消息

       1) put机制: ui端来控制，ui编辑完触发发送；24小时内每30分钟，触发最近所有未被confirm消息的发送；

          communication收到发送信号: put消息，发送信号（携带消息指针；
   	  
       2) forward机制: 无；
      
       3) get机制: 接收者收到信号，根据信号指针get消息，get到消息后put最新的10个confirm roots集合，并将其root用信号通知发送者，发送者获取信号之后根据root去get确认信息；

   note tx中保留链式结构(链接发送者发送的前1个消息)， 无nonce无tx fee

       1) put机制: ui端来控制: 编辑完触发发送；12小时内每30分钟，触发最近的10笔note tx发送(包括社区其他人的Note交易)；

          blockchain收到ui发送任务: 会执行put，并修改探索信号内容（携带note tx指针），面向接收者集合发送10次，每次间隔30s；

          blockchain本地交易池一把key只会保留3笔note tx；
   	  
       2) forward机制: 当探索信号转发note交易时，随机转发交易池时间戳排名前40的note交易指针；
      
       3) get机制: 收到信号后立即执行get，并会根据链式hash get 10笔note tx(需要设计数据库来记录已获得的note tx);

   news note tx中无链式结构, 有nonce有tx fee

       1) put机制：ui端控制, 编辑完触发发送(同时会触发最近一笔nonce交易的重发); 12小时内每30分钟，触发最近所有未上链的news note tx的发送；

          blockchain收到发送任务: 会执行put，并修改探索信号内容（携带note new tx指针），面向接收者集合发送10次，每次间隔30s；

          本地交易池一把key只会保留3笔交易（这个和所有未上链的news note tx笔数有一点冲突）；
   	  
       2) forward机制: 当探索信号转发news note tx交易时，随机转发交易池时间戳排名前40的news note交易指针；
      
       3) get机制: 收到信号后立即执行get，非链式结构，只get信号中指向的tx

   payment转账交易,有nonce有tx fee

       1) put机制: ui端发送控制, 编辑完触发发送(触发最近一笔nonce交易的重发)，当前nonce不一定会被发送(否则交易费策略会冲掉小nonce交易)

         链状态的修改会触发未上链的一笔（最近nonce）tx的发送，因为new note tx也有nonce

   	  当触发wiring coins tx交易发送时，同时触发p2p msgs，通知接收方转账行为；

          blockchain收到发送任务: 执行put，并修改探索信号内容（携带wiring coins tx指针）面向接收者集合发送10次，每次间隔30s；

   	  blockchain本地交易池一把key只会保留1笔交易（nonce是否合法；nonce如果都合法，取交易费大者）；

   	  communication收到发送wiring通知信号: 直接执行点对点消息发送；
   	  
       2) forward机制: 当探索信号转发payment交易时，转发交易池验证过的交易费最大的交易指针；
      
       3) get机制: 5分钟周期性执行get(get积累的所有转账交易信号里面最大的那一笔转账)，没有链式结构，只会get选中的这笔交易

    block

       1) put机制: 当矿工挖出新的head block时，会put整条链，包括所有block和state，然后向接收者集合发送信号（携带head block指针）10次，每次间隔30s
		  
       2) forward机制: 当探索信号转发区块信号时，转发本地以及打听到的链中最难的链的head block指针；
	   
       3) get机制: 5分钟周期性执行get，get打听到的最难的并超过本地链上的区块

概念补充：

1. 探索信号发送策略

	探索信号有自己的频率（根据策略计算得到），每次频率到了必定会发一个探索信号；
 	探索信号携带什么信息是有概率的；

		1) 假如自己存在发送行为（消息、交易），就有10个间隔30s任务，
		   如果这个10个任务没发完，会优先看一下间隔时间是否到了，间隔到了就会发这个；
							 
		2) 如果没到时间或者10个都发完了，会概率性选择携带head block或者交易；

			a) 如果选择head block，就会携带打听到的最难的head block；

			b) 如果选择的是交易，目前区分到3种交易；
            
				note和news交易在最近40笔中随机选择1笔，修改探索信号内容（携带交易指针），面向接收者集合发送1次，不执行put；
			
                wiring交易选择一笔交易费最大者，修改探索信号内容（携带交易指针），面向接收者集合发送1次，不执行put；

2. 接收者集合

   当前chain中的访问列表
