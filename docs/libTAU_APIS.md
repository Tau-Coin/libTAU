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
