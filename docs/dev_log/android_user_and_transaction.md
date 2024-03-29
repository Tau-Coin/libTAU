# 用户状态

 - consensus state
 
    从libTAU中通过state alert来获取更新
 
 	目前记录了consensusBalance, consensusPower, consensusNonce

 - latest onchain state
   
   从libTAU中通过getAccountInfo来获取
   
   目前记录了balance, power, nonce

   			mining power = log2(2 + power)

 - totalPendingAmount
 
 	从consensus点到目前(包括暂时上链 + 没有上链)一共花了多少钱，不考虑收入

- offchainPendingAmount

	从head block点到目前(只包括没有上链部分)一共花了多少钱，不考虑收入

# 当前用户余额相关统计

 - Interim Balance:
 		修改前: balance - offchainPendingAmount + 透支额度(100)
 		修改后: consensusBalance - totalPendingAmount + 透支额度(100)

- Payment Balance: 
		consensusBalance - totalPendingAmount

- Mining Rewards:
        power * 出块奖励(10)

- Pending Amount:
		(power - consensusPower) * 出块奖励(10) + 交易(onchain + offchain的支出和收入总差额)

- Wallet Transactions二级菜单:

    Pending Amount的条目显示
   - (Mining Rewards) (power - consensusPower) * 出块奖励(10)
   - 支出(news(fee) + wiring coins(fee + amount))
   - 收入(他人wiring coins(amount), 收到p2p转账消息也会显示)

# 交易类型

## 1. News交易

   Home页和Community页面右下角+进入交易的构建，构建好进入本地交易队列(需要重发)和交易数据库
   
 - 内容

       用户:  Content(450限制) + link + fee(默认值)
        
       andorid端: 交易信息补充 + 签名

           nonce:(最重要) 本地数据库中当前chain交易队列中最大nonce + 1
        
 - 发送机制
  
 		1) 构建好后会立即发送
        
         2) 本地交易队列有变动或者当前链状态发生改变会重发最近nonce(参考latest onchain nonce)的一笔
         			 latest onchain nonce的使用和NewHeadBlockAlert相结合，当head block存在时，则更新 >= latest onchain nonce的交易为offchain的状态，并且发送一笔最小noce的offchain交易;
         3) 12小时内的News消息，每隔30分钟，重发所有news交易(所有chainID)-以当前nonce(latest onchain nonce)为参考标准 + 交易创建时间，因为libTAU中News交易池不做验证，只要时间允许都可以进入
         

## 2. Note交易

   消息Chat进入交易的构建，构建好直接发送，进入交易数据库。
   
 - 内容
      
      用户: content(?限制)
      
      andorid端: 交易信息补充 + 签名

          previous hash, 当前用户发送的Note消息，形成链状结构
        
- 发送机制

       1) 构建好后会立即发送
       
       2) 12小时内的Notes消息，每隔30分钟，重发最近10笔Notes交易(所有chainID)-以交易创建时间为参考标准
       
## 3. WiringCoins交易

   Wanllet页和Community状态栏Pay people进入交易的构建，构建好进入本地交易队列(需要重发)和交易数据库
   
 - 内容

       用户: receiver + amount  + memo(?限制) + fee(默认值)
        
       andorid端: 交易信息补充 + 签名

           nonce: 本地数据库中当前chain交易队列中最大nonce + 1
        
 - 发送机制
 
       1) 构建好后会立即发送
       
       2) 本地交易队列有变动或者当前链状态发生改变会重发最近nonce(参考latest onchain nonce)的一笔
			
            	因为libTAU中WiringCoins交易池做验证，只允许合法nonce的wiring coins交易，如果nonce一致，则选择交易费大的一笔，这种机制决定了WiringCoins的交易发送机制
