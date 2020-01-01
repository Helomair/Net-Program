執行方式:
	1. make
	2. ./server_v1.c (開啟server端)
	3. ./client_v1.c 0.0.0.0 (新增client端)

封包格式:

1. add_user_neame:	輸入指令: "1 Apple"		接收server訊息: "1 1"
2. show:			輸入指令: "2"			接收server訊息: "2 apple banana " (直接印給apple)
3. Apple invite Banana:	輸入指令: "3 Apple Banana"

4. Banana接收server訊息: "4 Apple invite Banana"	
5. Banana的回應:	
	不接受 => 輸入指令: "5 0 Apple" 
	接受 => 輸入指令: "5 1 Apple"
6. Apple & Banana接收server訊息: 
	"6" => 開始遊戲，印出棋盤	


棋盤格式:
int board[9] = "0";
 0: 未使用
 1: 邀請者使用
 2: 被邀者使用

棋盤可能為 board = [0][1][-1][0]...[0]
陣列位置:           0  1  2   3     8

7. while(1){
	輸入指令: "0~8\n" (想要的位置)	
	先修改陣列board，再回傳board => 最終傳給server格式: "7  0 0 2 0 1 1 0 0" ("7 board長相")

	接收server訊息: "8  0 0 2 2 1 1 0 0 Apple_turn" ("8 board長相 狀態")
}

8. 登出:			 輸入指令: "logout"




作業要求：
	請設計一對client--server的OX棋下棋程式，具有下列幾個特性：
	1. 允許多個client同時登錄至server。
	2. client的使用者可以列出所有已登入的使用者名單。
	3. client的使用者可以選擇要跟哪一個使用者下棋，並請求對方的同意。
	4. 若對方同意後，開始進入棋局。
	5. 雙方可輪流下棋，直到分出勝負或平手。
	6. 登入的使用者可選擇登出。

	ps.
	1. 前述未詳盡指定的規格，同學可以用對自己最方便的方式自行定義。
	2. 指令或執行畫面(例如棋盤...)，同學可自行定義。
	3. 為方便起見，使用者的帳號與密碼可事先內建在server中，不用提供註冊功能。
