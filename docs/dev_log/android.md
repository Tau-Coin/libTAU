# Android开发任务列表

## 2022.06.22
### 任务列表

- 如果3分钟内（固定参数）用户和TAU app没有“鼠标键盘手指交互”和“doze过”就进入“TAU 休息模式”。TAU休息模式时，app根据电池和网络流量剩余来间歇工作（根据两个指标较低剩余百分比90%（包括充电状态），70%，50%，30%，10%可以定休眠时间长度），目前先就先采用“区块链业务进程挂起”相应0，3，6，12，24分钟策略。当用户从休眠状态启动交互，区块链模块要被唤醒。
 	- 问题：3分钟执行定时后，是否要根据流量和电池情况再次调整挂起时间了？方案：直接唤醒，重新开始3分钟内；
	- 计算libTAU休眠时间显示；
- all states上报，本地更新
	- 可以在members里面把余额和power现实出来。
	- 社区的members X, g Y, c Z,   X，Y，Z可以点击，进入相应的列表。
- 现在有了缓存，可以把小照片put在缓存厘米，就不用传递了。
- 流量包设置
	- 发达地区：wifi不计算流量，telecome:100/500/1G; 
	- 落后地区：wifi: 100/300/600; telecom： 30/100/300

## 已完成
<table>
	<tr>
		<th>序号</th>
		<th>任务名称</th>
		<th>进度（%）</th>
		<th>优先级</th>
		<th>备注</th>
	</tr>
	<tr>
    	<td >1</td>
		<td >Airdrop分享逻辑</td>
		<td>100</td>
		<td>2</td>
		<td></td>
    </tr>
    <tr>
    	<td>2</td>
		<td>Alert缺失，信息状态不对，提供重新加载链数据的入口</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
     <tr>
    	<td>3</td>
		<td >账户过期逻辑修改？</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>4</td>
		<td>交易重发策略</td>
		<td> 100 </td>
		<td>0</td>
		<td></td>
    </tr>
	<tr>
    	<td>5</td>
		<td >添加好友未回复消息，friend状态提示</td>
		<td>100</td>
		<td>0</td>
		<td></td>
    </tr>
    <tr>
    	<td>6</td>
		<td>Balances和communities合并</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>7</td>
		<td>Chain Status显示出块倒计时</td>
		<td>100</td>
		<td>0</td>
		<td></td>
    </tr>
    <tr>
    	<td>8</td>
		<td >流量策略：前台加入流量包限制</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>9</td>
		<td >用户当前关注链，传给libTAU</td>
		<td>90</td>
		<td>0</td>
		<td></td>
    </tr>
    <tr>
    	<td>10</td>
		<td >join phone swarm去掉，仿微信顶部显示</td>
		<td>100</td>
		<td>0</td>
		<td></td>
    </tr>
    <tr>
    	<td>11</td>
		<td >交易收藏</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>12</td>
		<td>附近社区模块</td>
		<td> 100 </td>
		<td>0</td>
		<td></td>
    </tr>
    <tr>
    	<td>13</td>
		<td>Android版本升级</td>
		<td> 100 </td>
		<td>0</td>
		<td></td>
    </tr>    
    <tr>
    	<td>14</td>
		<td >消息发送状态：发送中，显示黄色；受到回执是绿色；失败是红色；类似路灯设计，提高用户体验。</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>15</td>
		<td >ready only -> notes only不上链用户可以发消息</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>16</td>
		<td >创建社区时，放一笔coins sell的交易在负一区块或零区块</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>17</td>
		<td>Blocks添加详细信息</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>18</td>
		<td >Communities改版，先显示列表，再显示详情</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>19</td>
		<td>首页社区非成员添加join入口</td>
		<td>100</td>
		<td>1</td>
		<td></td>
    </tr>
    <tr>
    	<td>20</td>
		<td>低配置手机数据排序查询慢</td>
		<td>100</td>
		<td>1</td>
		<td>添加数据库索引</td>
    </tr>
</table>
