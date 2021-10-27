# libTAU APIs


## 状态相关

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

## Blockchain业务相关

### 区块链暴露供外部使用的数据结构

	创世区块账户信息
	class GenesisAccount {
		byte[] account;
		BigInteger balance;
		BigInteger power;
	}
	
	创世区块结构
	class GenesisConfig {
		GenesisConfig(String communityName, List<GenesisAccount> genesisItems);
		byte[] getChianID();
	}

	区块结构
	class Block {
		...
	}
	
	交易结构
	class Transaction {
		...
	}
	
	交易类型
	enum TransactionType {
		...
	}
	
	Offchain message
	class ChianMessage {
		String chainID;
		String senderPk;
		String msg;
		...
	}
	
	账户信息
	class AccountInfo {
		BigInteger balance;
		BigInteger nonce;
	}
	
	链URL结构组织（tauchain:?bs=pk1&bs=pk2&dn=chainID）
	URL中的tauchain为小写字母
	class ChainUrl {
		String encode(String chainID, List<String> publicKeys);
		ChainUrl decode(String link);
	}
	
### 区块链外部可调用的接口
	
	创建新的社区
	boolean createNewCommunity(GenesisConfig cf);
	
	提交交易到交易池
	boolean submitTransaction(Transaction tx);

	send Offchain message
	boolean sendChianMessage(ChianMessage msg);
	
	获取账户信息
	AccountInfo getAccountInfo(String chainID, String publicKey);
	
	跟随链
	followChain(ChainUrl url);
	
	取消跟随链
	unfollowChain(String chainID);
	
	获取当前分叉点Block
	void getCurrentForkBlock(Block block);
	
	获取共识点投票前三名的区块号和哈希
	List<Block> getTopConsensusBlock(String chainID, int topNum);
	
	获取tip前三名区块号和哈希
	List<Block> getTopTipBlock(String chainID, int topNum);
	
### 区块链上报的接口
	
	新的区块
	void onNewBlock(Block block);
	
	同步区块
	void onSyncBlock(Block block);
	
	区块回滚
	void onBlockRollback(Block block);
	
	new Offchain message
	void onNewChianMessage(ChianMessage msg);
	
	
	
	