# libTAU APIs


## 状态相关

### 时间信息
	std::int64_t get_session_time();

### 网络状态
	// total download rate
    int total_download_rate();
    
    // total download
    int total_download_rate();
    
    // total upload rate
    int total_upload_rate();
    
    // total upload
    int total_upload_rate();
## 设置相关

### 账户系统
	// set new account seed
	void new_account_seed(std::array<char, 32> seed);
### 设置参数
	// apply settings
	void apply_settings(settings_pack const&);
### 网络设置
	// starts and stops the UPnP service.
    void start_upnp();
    void stop_upnp();

    // starts and stops the NAT-PMP service.
    void start_natpmp();
    void stop_natpmp();


## Communication业务相关
### 设置主循环频率
	// set main loop time interval (ms)
    void set_loop_time_interval(int milliseconds);

### 朋友操作
	// add new friend in memory & db
	bool add_new_friend(std::array<char, 32> pubkey);

	// delete friend and all related data in memory & db
	bool delete_friend(std::array<char, 32> pubkey);

	// get friend info by public key
	std::vector<char> get_friend_info(std::array<char, 32> pubkey);

	// save friend info
	bool update_friend_info(std::array<char, 32> pubkey, std::vector<char> friend_info);

	// set active friends
	void set_active_friends(std::vector<std::array<char, 32>> active_friends);
	
	// set chatting friends
	void set_chatting_friend(std::array<char, 32> pubkey);

	// unset chatting friends
	void unset_chatting_friend();

### 信息操作
	// add a new message
	bool add_new_message(communication::message msg);

### Communication上报alert
	//　新的通讯device
	communication_new_device_id_alert
	
	// 新的信息
	communication_new_message_alert

	// 消息被确认
	communication_confirmation_root_alert

	// 消息被同步
	communication_syncing_message_alert

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
	链URL结构组织（tauchain:?bs=pk1&bs=pk2&dn=chainID）
	URL中的tauchain为小写字母
	ChainURL涉及到UTF-8编码, HEX编码,其中pk1, pk2...pkn采用HEX编码
	ChainID也有两类：
		1) TAU_CHAIN_ID
		2) hasher(pk+time) + CommunityName(最长24字节)
	*/	

### 区块链外部可调用的接口

	// 创建新的ChainID
	std::vector<char> create_chain_id(std::vector<char> community_name)
	
	// 创建新的社区
	bool create_new_community(std::vector<char> chain_id, const std::map<dht::public_key, blockchain::account>& accounts);

	// 跟随链
	bool follow_chain(const blockchain::chain_url & cul);

	// 取消跟随链
	bool unfollow_chain(std::vector<char> chain_id);

	// 提交交易到交易池
	bool submit_transaction(const blockchain::transaction & tx);

	// 获取账户信息
	blockchain::account get_account_info(std::vector<char> chain_id, dht::public_key publicKey);

	// 获取tip前三名区块号和哈希
	std::vector<blockchain::block> get_top_tip_block(std::vector<char> chain_id, int num);

	// 获取交易打包的中值交易费
	std::int64_t get_median_tx_free(std::vector<char> chain_id);

	// 获取区块
	blockchain::block get_block_by_number(std::vector<char> chain_id, std::int64_t block_number);
	blockchain::block get_block_by_hash(std::vector<char> chain_id, sha256_hash block_hash);
	
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
    
	新交易
	blockchain_new_transaction_alert
	
    共识点投票前三名的区块
    blockchain_top_three_votes_alert
