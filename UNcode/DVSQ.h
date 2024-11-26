#ifndef DVSQ_H  // 防止头文件被重复包含 
#define DVSQ_H
#include <iostream>
#include <fstream>
#include <vector>
#include <limits>
#include <cmath>
#include <algorithm>
#include <ctime>
#include <float.h>
#include <string> 
#include <string.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <random>
#include <cmath>
#include <sstream>
#include "paillier.h"
#include "AES.h"
#include "algo_hmac.h"
using namespace std;
#define SERVER_NUM 4
#define LAMBDA 4
#define THETA 0.1  //最小假点添加率 
#define KEY_LEN_BIT 512
#define N 1

//结构体用于存储数据点明文 
struct DataPoint{
	float x;
	float y;
};

//结构体用于存储paillier加密后的数据点密文 
struct PaiEncPoint{
	mpz_t eX;
	mpz_t eY;
	PaiEncPoint(){
		mpz_inits(eX, eY, NULL);
	}
}; 

//结构体用于存储小网格坐标 
struct Coordinate{
	int x;
	int y;
};

//结构体用于表示矩形 
struct Rectangle{
	float minX;
	float maxX;
	float minY;
	float maxY;
};

//结构体用于表示paillier加密矩形 
struct ERectangle{
	mpz_t eMinX;
	mpz_t eMaxX;
	mpz_t eMinY;
	mpz_t eMaxY;
	ERectangle(){
		mpz_inits(eMinX, eMaxX, eMinY, eMaxY, NULL);
	}
};

//结构体用于表示小网格 
struct Grid{
//	int tag;  //随机数->验证置换操作 
	Rectangle rect;  //小网格范围 
	ERectangle eRect;  //范围密文 
	vector<DataPoint> dataPoints;  //小网格包含的数据点 
	char *eDataPoints;  //加密后的密文数据 
	int eDLen;   
	Coordinate p;  //小网格坐标 
	char *eP;  //坐标密文
	int ePLen; 
	string hashValue;  //哈希值 
	Grid(){
		hashValue = "";
		eDataPoints = NULL;
		eP = NULL;
	}
};

//结构体用于记录一个存储服务器内容 
struct Server{
	Rectangle rect;
	ERectangle eRect;
	vector<DataPoint> dataPoints;
	int Px, Py;
	vector<vector<Grid> > gridSet;
};

//结构体用于记录验证信息表的某一行信息 
struct VeriTable{
	int serverID;
	int eHashLen;
	char* eHash;
	VeriTable(){
		eHash = NULL;
	}
}; 

//结构体用于记录单个服务器返回的查询结果及验证信息 
struct SubResult{
	vector<Grid> result;  
	vector<string> veriInfo;  
	VeriTable veriTable;
};

//数据拥有者类 
class DataOwner {
public:
	//成员函数  
    DataOwner();  //构造函数
	DataOwner(phe::PaillierKey pubKey, phe::PaillierPrivateKey privateKey, string fixAesKey, string realTimeAesKey, string hashKey);  //带参数的构造函数 
	PaiEncPoint getTrapdoor(DataPoint q, phe::Paillier pai);  //传入查询点，返回查询陷门 
	bool verification(DataPoint q, phe::Paillier pai, vector<vector<int> > colReversePermutations, vector<vector<int> > rowReversePermutations);  //验证结果集 
	void resultDecrypt();  //解密最终结果
	void insertPoint(DataPoint p);  //插入点 
	void deletePoint(DataPoint p);  //删除点 
	int updateGrid();  //更新小网格密文和哈希值 
	vector<VeriTable> updateVeriTable(int sID);  //更新验证信息表 
	void updateRealTimeAesKey();  //更新实时密钥 
	Coordinate relocationGrid(int sID, vector<int> colPermuList, vector<int> rowPermuList);
	~DataOwner();  //析构函数 
    
	//成员变量 
	phe::PaillierKey pubKey;  //paillier公钥 
    phe::PaillierPrivateKey privateKey;  //paillier私钥 
    string fixAesKey;  //AES固定密钥 
    string realTimeAesKey;  //AES实时密钥 
	string hashKey;  //哈希密钥 
	vector<SubResult> FinalResult;  //记录最终的查询结果
};

//数据使用者类 
class DataUser {
public:
	//成员函数  
    DataUser();  //构造函数
	DataUser(phe::PaillierKey pubKey, phe::PaillierPrivateKey privateKey, string fixAesKey, string realTimeAesKey, string hashKey);  //带参数的构造函数 
	ERectangle getTrapdoor(Rectangle Q, phe::Paillier pai);  //传入查询范围，返回查询陷门 
	bool verification(Rectangle Q, phe::Paillier pai, vector<vector<int> > colReversePermutations, vector<vector<int> > rowReversePermutations);  //验证 
	void resultDecrypt();  //解密最终结果 
	pair<int, int> resultRefine(Rectangle Q);  //结果精炼 
	~DataUser();  //析构函数 
    
	//成员变量 
	phe::PaillierKey pubKey;  //paillier公钥 
    phe::PaillierPrivateKey privateKey;  //paillier私钥 
    string fixAesKey;  //AES固定密钥 
    string realTimeAesKey;  //AES实时密钥 
	string hashKey;  //哈希密钥 
	vector<SubResult> FinalResult;  //记录最终的查询结果 
};

//传输服务器类 
class TransmissionServer {
public:
	//成员函数 
	TransmissionServer();  //构造函数
	TransmissionServer(vector<VeriTable> veriTable);  //带参数的构造函数 
	~TransmissionServer();  //析构函数 
	void receiveResult(vector<Grid> result, vector<string> veriInfo);  //回收查询结果 
	void summaryResult(int signal);  //整合查询结果, signal：0-->范围查询，1-->点查询
	void setEmpty();  //将结果集置空 
	
	//成员变量  
    vector<VeriTable> veriTable;  //用于后期验证的table
	vector<SubResult> FinalResult;  //记录最终的查询结果 
};

//计算服务器类 
class ComputingServer {
public:
	//成员函数
	ComputingServer();  //构造函数
	ComputingServer(phe::PaillierKey pubkey, phe::PaillierPrivateKey privateKey, string hashKey);  //带参数的构造函数 
	~ComputingServer();  //析构函数 
	 
    //成员变量 
	phe::PaillierKey pubkey;  //paillier公钥 
    phe::PaillierPrivateKey privateKey;  //paillier私钥 
    string hashKey;  //哈希密钥 
};

//存储服务器类 
class StorageServer {
public:
	//成员函数 
	StorageServer();  //构造函数
	StorageServer(ERectangle eRect, vector<vector<Grid> > gridSet);  //带参数的构造函数 
    int genRandom();  //生成随机数 
    void setEmpty();  //将结果集和验证信息置空 
	~StorageServer();  //析构函数 
	 
	//成员变量 
	ERectangle eRect;  //子集范围 
	vector<vector<Grid> > gridSet;  //加密网格 
	ERectangle eQ;  //范围查询陷门 
	PaiEncPoint eq;  //点查询陷门 
	vector<Grid> result;  //保存查询结果和部分验证信息 
	vector<string> veriInfo;  //保存部分验证信息 
};

//读取文件
vector<DataPoint> readFile(char filename[]);

//获取数据集所在大矩形
Rectangle getDataRange(vector<DataPoint> dataPoints);

//给定Server的数量，获取大子集划分情况 
pair<int, int> getClosestFactor(int num);

//为每个Server划分子集 
void partition(Rectangle rect, pair<int, int> factors, Server serv[SERVER_NUM], vector<DataPoint> dataPoints); 

//为每个子集划分小网格 且 求出最大的网格宽度
int divideGrid(Server &serv);

//添加假点
void addFakePoints(int maxWidth, Server &serv, float theta); 

//数据加密
void dataEncryption(Server &serv, phe::Paillier pai, string fixAesKey);

//计算哈希值 
void hashSign(Server &serv, string hashKey);

//生成验证信息表 
char* geneVeriTable(Server serv, string realTimeAesKey, int &len);

//生成初始置换列表 
vector<int> getPermuList(int n);

//生成逆置换列表 
vector<int> getReversePermuList(vector<int> permuList, int n);

//列置换函数
void colPermutation(vector<vector<Grid> >& grid, const vector<int>& permuList);
void colPermutation(string &s, const vector<int>& permuList);

//行置换函数
void rowPermutation(vector<vector<Grid> >& grid, const vector<int>& permuList);

//SS的范围查询线程处理函数 
void Qthread_SS(StorageServer &SS, ComputingServer CS, ERectangle eQ, phe::Paillier pai); 

//SS的点查询线程处理函数 
void qthread_SS(StorageServer &SS, ComputingServer CS, PaiEncPoint eq, phe::Paillier pai);  

//从字符串中提取出加密矩形 
vector<string> segmentStr(string str, char c);

//从字符串中提取出数据点 
vector<DataPoint> segmentValueStr(unsigned char *data, char c1, char c2);

//读取测试文件
vector<Rectangle> readTestFile(char filename[]);
#endif  

