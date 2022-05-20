# libTAU APIs


## 状态相关

### 时间信息
    std::int64_t get_session_time();
    1) <= 0: 时间获取出错
    2) > 0: 时间获取正常

## 设置相关

### 设置参数
    // apply settings
    void apply_settings(settings_pack const&);

## Communication业务相关

### 设置主循环频率
```    
    // 事件触发方案下已废弃
    // set main loop time interval (ms)
    //std::uint8_t set_loop_time_interval(int milliseconds);
    //1) 0: 时间间隔设置正常
    //2) >0: 时间间隔设置非正常(session_impl来控制管理)
    //   1: communication设置异常
    //   2: blockchain设置异常
    //   3: communication && blockchain设置异常
```

### 朋友操作
```
    // add new friend in memory & db
    std::uint8_t add_new_friend(std::array<char, 32> pubkey);
    1) 0: 朋友添加正常
    2) >0: 朋友添加非正常(具体错误代码后续再添加)
        1: pubkey解析异常（长度、内容等）
       
    // delete friend and all related data in memory & db
    std::uint8_t delete_friend(std::array<char, 32> pubkey);
    1) 0: 朋友删除正常
    2) >0: 朋友删除非正常(具体错误代码后续再添加)
        1: pubkey解析异常（长度、内容等）
        2: 朋友不存在

    // get friend info by public key
    std::vector<char> get_friend_info(std::array<char, 32> pubkey);
    1) NULL: 朋友信息获取失败，不存在
    2) 非NULL: Android端注意朋友信息相关的解析，需考虑数据不正常行，进行异常处理；

    // save friend info
    std::uint8_t update_friend_info(std::array<char, 32> pubkey, std::vector<char> friend_info);
    1) 0: 朋友信息更新正常
    2) >0: 朋友信息更新非正常(具体错误代码后续再添加)
        1: pubkey解析异常
        2: pubkey不存在

    // set active friends
    std::uint8_t set_active_friends(std::vector<std::array<char, 32>> active_friends);
    1) 0: 活跃朋友设置正常
    2) >0: 活跃朋友设置非正常(具体错误代码后续再添加)
        1: pubkey解析异常
        2: pubkey不存在
    
    // 事件触发方案下已废弃
    // set chatting friends
    //std::uint8_t set_chatting_friend(std::array<char, 32> pubkey);
    //1) 0: 聊天朋友设置正常
    //2) >0: 聊天朋友设置非正常(具体错误代码后续再添加)
    //    1: pubkey解析异常
    //    2: pubkey不存在

    // 事件触发方案下已废弃
    // unset chatting friends
    //std::uint8_t unset_chatting_friend();
    //1) 0: 聊天朋友取消正常
    //2) >0: 聊天朋友取消非正常(具体错误代码后续再添加)
```
### 信息操作
    // add a new message
    std::uint8_t add_new_message(communication::message msg);
    1) 0: 聊天信息发送正常
    2) >0: 聊天信息发送非正常(具体错误代码后续再添加)
       1: 发送者解析错误
       2: 接收者解析错误
       3：接收者(朋友)不存在

### Communication上报alert
    //　新的通讯device
    communication_new_device_id_alert
    
    // 新的信息
    communication_new_message_alert

    // 消息被同步
    communication_syncing_message_alert

    // 消息被送达
    communication_message_arrived_alert

    // 消息被确认
    communication_confirmation_root_alert

    // 新的朋友
    communication_friend_info_alert

    // 朋友最新在线时间
    communication_last_seen_alert

## Blockchain业务相关

### 区块链暴露供外部使用的数据结构
    // 区块结构
    class Block {
        ...
    }
    
    // 交易结构
    class Transaction {
        ...
    }
    
    // 账户信息
    class Account {
        ...
    }
    
    // 投票信息
    class Vote {
        ...
    }

    // 链端命名    
    class ChainURL {
        ...
    }
    /*
    链URL结构组织（tauchain:?dn=chainID&bs=pk1&bs=pk2）
    URL中的tauchain为小写字母
    ChainURL涉及到UTF-8编码, HEX编码,其中pk1, pk2...pkn采用HEX编码
    ChainID也有两类：
        1) TAU_CHAIN_ID
        2) hasher(pk+time) + CommunityName(最长24字节)
    */    

### 区块链外部可调用的接口

    // 创建新的ChainID
    std::vector<char> create_chain_id(std::vector<char> community_name)
    1) NULL: 创建ChainID失败（原因未知）
    2) 非NULL: Android端注意ChainID的解析，需考虑数据不正常行，进行异常处理； 
    
    // 创建新的社区
    std::uint8_t create_new_community(std::vector<char> chain_id, const std::map<dht::public_key, blockchain::account>& accounts);
    1) 0: 创建新社区正常
    2) > 0: 创建新社区非正常(具体错误代码后续再更新)
        1: ChainID解析异常
        2: accounts解析异常
    // 跟随链
    std::uint8_t follow_chain(std::vector<char> chain_id, const std::set<dht::public_key>& peers);
    1) 0: Follow社区正常
    2) > 0: Follow社区非正常(具体错误代码后续再更新)
        1: ChainID解析异常
        2: peers解析异常
        
    //添加新的Boostrap节点
    std::uint8_t add_new_bootstrap_peers(std::vector<char> chain_id, const std::set<dht::public_key>& peers);
    1) 0: 新BS节点添加正常
    2) > 0: 新BS节点添加非正常(具体错误代码后续再更新)
        1: ChainID解析异常
        2: peers解析异常
        
    // 取消跟随链
    std::uint8_t unfollow_chain(std::vector<char> chain_id);
    1) 0: Unfollow社区正常
    2) > 0: Unfollow社区非正常(具体错误代码后续再更新)
        1: ChainID解析异常
        2: ChainiD不存在
        
    // 提交交易到交易池
    std::uint8_t submit_transaction(const blockchain::transaction & tx);
    1) 0: 交易提交正常
    2) > 0: 交易提交非正常(具体错误代码后续再更新)
        1: ChainID不存在
        2: 超额()
        
    // 获取账户信息
    blockchain::account get_account_info(std::vector<char> chain_id, dht::public_key publicKey);
    1) NULL: 获取账户信息失败（原因未知，ChainID pubkey不存在）
    2) 非NULL: swig端注意account的解析，需考虑数据不正常行，进行异常处理；
    
    // 获取tip前三名区块号和哈希
    std::vector<blockchain::block> get_top_tip_block(std::vector<char> chain_id, int num);
    1) NULL: 获取TopTipBlock失败（原因未知，ChainID不存在）
    2) 非NULL: swig端注意block的解析，需考虑数据不正常行，进行异常处理；
    
    // 获取区块
    blockchain::block get_block_by_number(std::vector<char> chain_id, std::int64_t block_number);
    1) NULL: 获取Block失败（原因未知，ChainID、number不存在）
    2) 非NULL: swig端注意block的解析，需考虑数据不正常行，进行异常处理；
    
    blockchain::block get_block_by_hash(std::vector<char> chain_id, sha256_hash block_hash);
    1) NULL: 获取Block失败（原因未知，ChainID、hash不存在）
    2) 非NULL: swig端注意block的解析，需考虑数据不正常行，进行异常处理；
    
    // 获取交易打包的中值交易费
    std::int64_t get_median_tx_free(std::vector<char> chain_id);
    1) < 0: chain_id解析异常
    2) == 0: chain_id不存在
    2) > 0: 正常中值交易费获取正常
    
    //判断交易是否在池
    std::uint8_t is_transaction_in_fee_pool(std::vector<char> chain_id, const sha256_hash& txid);
    1) 0: 交易在池
    2) > 0: 交易不在交易池或者出错
        1: 交易不在交易池
        2: chain_id解析异常
        3: txid解析异常
        4: chain_id不存在
        
    // get access list
    std::set<dht::public_key> get_access_list(std::vector<char> chain_id);
    1) NULL: 获取Access列表失败（原因未知，chain_id不存在）
    2) 非NULL: swig端注意Pubkey的解析，需考虑数据不正常行，进行异常处理；
    
    // get ban list
    std::set<dht::public_key> get_ban_list(std::vector<char> chain_id);
    1) NULL: 获取Ban列表失败（原因未知，chain_id不存在）
    2) 非NULL: swig端注意Pubkey的解析，需考虑数据不正常行，进行异常处理；
    
    // get gossip list
    std::set<dht::public_key> get_gossip_list(std::vector<char> chain_id);
    1) NULL: 获取Gossip列表失败（原因未知，chain_id不存在）
    2) 非NULL: swig端注意Pubkey的解析，需考虑数据不正常行，进行异常处理；

    // get mining time
    std::int64_t get_mining_time(std::vector<char> chain_id);
    1) == -2: chain_id不存在
    2) == -1: chain_id解析异常
    2) >= 0: 正常中值交易费获取正常
    
    // 事件触发方案下已废弃
    // focus on chain
    //std::uint8_t set_priority_chain(std::vector<char> chain_id);
    //1) 0: 设置优先链正常
    //2) > 0: 设置优先链非正常(具体错误代码后续再更新)
    //    1: chain_id解析异常
    //    2: chain_id不存在

    // 事件触发方案下已废弃
    // un-focus on chain
    // std::uint8_t unset_priority_chain();
    // 1) 0: 取消优先链正常
    // 2) > 0: 取消优先链非正常(具体错误代码后续再更新)
    
    //请求链状态，以alert上报
    std::uint8_t request_chain_state(const aux::bytes &chain_id)
    1) 0: 获取链状态正常
    2) > 0: 获取链状态非正常(具体错误代码后续再更新)
        1: chain_id解析异常
        2: chain_id不存在
        
### 区块链上报的alert
    新的头部区块
    blockchain_new_head_block_alert
    
    新的尾部区块
    blockchain_new_tail_block_alert
    
    新的共识区块    
    blockchain_new_consensus_point_block_alert
    
    回滚的区块
    blockchain_rollback_block_alert
    
    当前分叉点Block
    blockchain_fork_point_block_alert
    
    共识点投票前三名的区块
    blockchain_top_three_votes_alert
    
    新交易
    blockchain_new_transaction_alert
    
    blockchain_state_alert
    
    blockchain_syncing_block_alert
    
    // this alert is posted when syncing head block.
    blockchain_syncing_head_block_alert
    
    // 暂未使用
    //交易确认
    //blockchain_tx_confirmation_alert

    // 交易被发送
    blockchain_tx_sent_alert

    // 交易被送达
    blockchain_tx_arrived_alert
