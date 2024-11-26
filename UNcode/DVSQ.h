#ifndef DVSQ_H  // ��ֹͷ�ļ����ظ����� 
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
#define THETA 0.1  //��С�ٵ������ 
#define KEY_LEN_BIT 512
#define N 1

//�ṹ�����ڴ洢���ݵ����� 
struct DataPoint{
	float x;
	float y;
};

//�ṹ�����ڴ洢paillier���ܺ�����ݵ����� 
struct PaiEncPoint{
	mpz_t eX;
	mpz_t eY;
	PaiEncPoint(){
		mpz_inits(eX, eY, NULL);
	}
}; 

//�ṹ�����ڴ洢С�������� 
struct Coordinate{
	int x;
	int y;
};

//�ṹ�����ڱ�ʾ���� 
struct Rectangle{
	float minX;
	float maxX;
	float minY;
	float maxY;
};

//�ṹ�����ڱ�ʾpaillier���ܾ��� 
struct ERectangle{
	mpz_t eMinX;
	mpz_t eMaxX;
	mpz_t eMinY;
	mpz_t eMaxY;
	ERectangle(){
		mpz_inits(eMinX, eMaxX, eMinY, eMaxY, NULL);
	}
};

//�ṹ�����ڱ�ʾС���� 
struct Grid{
//	int tag;  //�����->��֤�û����� 
	Rectangle rect;  //С����Χ 
	ERectangle eRect;  //��Χ���� 
	vector<DataPoint> dataPoints;  //С������������ݵ� 
	char *eDataPoints;  //���ܺ���������� 
	int eDLen;   
	Coordinate p;  //С�������� 
	char *eP;  //��������
	int ePLen; 
	string hashValue;  //��ϣֵ 
	Grid(){
		hashValue = "";
		eDataPoints = NULL;
		eP = NULL;
	}
};

//�ṹ�����ڼ�¼һ���洢���������� 
struct Server{
	Rectangle rect;
	ERectangle eRect;
	vector<DataPoint> dataPoints;
	int Px, Py;
	vector<vector<Grid> > gridSet;
};

//�ṹ�����ڼ�¼��֤��Ϣ���ĳһ����Ϣ 
struct VeriTable{
	int serverID;
	int eHashLen;
	char* eHash;
	VeriTable(){
		eHash = NULL;
	}
}; 

//�ṹ�����ڼ�¼�������������صĲ�ѯ�������֤��Ϣ 
struct SubResult{
	vector<Grid> result;  
	vector<string> veriInfo;  
	VeriTable veriTable;
};

//����ӵ������ 
class DataOwner {
public:
	//��Ա����  
    DataOwner();  //���캯��
	DataOwner(phe::PaillierKey pubKey, phe::PaillierPrivateKey privateKey, string fixAesKey, string realTimeAesKey, string hashKey);  //�������Ĺ��캯�� 
	PaiEncPoint getTrapdoor(DataPoint q, phe::Paillier pai);  //�����ѯ�㣬���ز�ѯ���� 
	bool verification(DataPoint q, phe::Paillier pai, vector<vector<int> > colReversePermutations, vector<vector<int> > rowReversePermutations);  //��֤����� 
	void resultDecrypt();  //�������ս��
	void insertPoint(DataPoint p);  //����� 
	void deletePoint(DataPoint p);  //ɾ���� 
	int updateGrid();  //����С�������ĺ͹�ϣֵ 
	vector<VeriTable> updateVeriTable(int sID);  //������֤��Ϣ�� 
	void updateRealTimeAesKey();  //����ʵʱ��Կ 
	Coordinate relocationGrid(int sID, vector<int> colPermuList, vector<int> rowPermuList);
	~DataOwner();  //�������� 
    
	//��Ա���� 
	phe::PaillierKey pubKey;  //paillier��Կ 
    phe::PaillierPrivateKey privateKey;  //paillier˽Կ 
    string fixAesKey;  //AES�̶���Կ 
    string realTimeAesKey;  //AESʵʱ��Կ 
	string hashKey;  //��ϣ��Կ 
	vector<SubResult> FinalResult;  //��¼���յĲ�ѯ���
};

//����ʹ������ 
class DataUser {
public:
	//��Ա����  
    DataUser();  //���캯��
	DataUser(phe::PaillierKey pubKey, phe::PaillierPrivateKey privateKey, string fixAesKey, string realTimeAesKey, string hashKey);  //�������Ĺ��캯�� 
	ERectangle getTrapdoor(Rectangle Q, phe::Paillier pai);  //�����ѯ��Χ�����ز�ѯ���� 
	bool verification(Rectangle Q, phe::Paillier pai, vector<vector<int> > colReversePermutations, vector<vector<int> > rowReversePermutations);  //��֤ 
	void resultDecrypt();  //�������ս�� 
	pair<int, int> resultRefine(Rectangle Q);  //������� 
	~DataUser();  //�������� 
    
	//��Ա���� 
	phe::PaillierKey pubKey;  //paillier��Կ 
    phe::PaillierPrivateKey privateKey;  //paillier˽Կ 
    string fixAesKey;  //AES�̶���Կ 
    string realTimeAesKey;  //AESʵʱ��Կ 
	string hashKey;  //��ϣ��Կ 
	vector<SubResult> FinalResult;  //��¼���յĲ�ѯ��� 
};

//����������� 
class TransmissionServer {
public:
	//��Ա���� 
	TransmissionServer();  //���캯��
	TransmissionServer(vector<VeriTable> veriTable);  //�������Ĺ��캯�� 
	~TransmissionServer();  //�������� 
	void receiveResult(vector<Grid> result, vector<string> veriInfo);  //���ղ�ѯ��� 
	void summaryResult(int signal);  //���ϲ�ѯ���, signal��0-->��Χ��ѯ��1-->���ѯ
	void setEmpty();  //��������ÿ� 
	
	//��Ա����  
    vector<VeriTable> veriTable;  //���ں�����֤��table
	vector<SubResult> FinalResult;  //��¼���յĲ�ѯ��� 
};

//����������� 
class ComputingServer {
public:
	//��Ա����
	ComputingServer();  //���캯��
	ComputingServer(phe::PaillierKey pubkey, phe::PaillierPrivateKey privateKey, string hashKey);  //�������Ĺ��캯�� 
	~ComputingServer();  //�������� 
	 
    //��Ա���� 
	phe::PaillierKey pubkey;  //paillier��Կ 
    phe::PaillierPrivateKey privateKey;  //paillier˽Կ 
    string hashKey;  //��ϣ��Կ 
};

//�洢�������� 
class StorageServer {
public:
	//��Ա���� 
	StorageServer();  //���캯��
	StorageServer(ERectangle eRect, vector<vector<Grid> > gridSet);  //�������Ĺ��캯�� 
    int genRandom();  //��������� 
    void setEmpty();  //�����������֤��Ϣ�ÿ� 
	~StorageServer();  //�������� 
	 
	//��Ա���� 
	ERectangle eRect;  //�Ӽ���Χ 
	vector<vector<Grid> > gridSet;  //�������� 
	ERectangle eQ;  //��Χ��ѯ���� 
	PaiEncPoint eq;  //���ѯ���� 
	vector<Grid> result;  //�����ѯ����Ͳ�����֤��Ϣ 
	vector<string> veriInfo;  //���沿����֤��Ϣ 
};

//��ȡ�ļ�
vector<DataPoint> readFile(char filename[]);

//��ȡ���ݼ����ڴ����
Rectangle getDataRange(vector<DataPoint> dataPoints);

//����Server����������ȡ���Ӽ�������� 
pair<int, int> getClosestFactor(int num);

//Ϊÿ��Server�����Ӽ� 
void partition(Rectangle rect, pair<int, int> factors, Server serv[SERVER_NUM], vector<DataPoint> dataPoints); 

//Ϊÿ���Ӽ�����С���� �� �������������
int divideGrid(Server &serv);

//��Ӽٵ�
void addFakePoints(int maxWidth, Server &serv, float theta); 

//���ݼ���
void dataEncryption(Server &serv, phe::Paillier pai, string fixAesKey);

//�����ϣֵ 
void hashSign(Server &serv, string hashKey);

//������֤��Ϣ�� 
char* geneVeriTable(Server serv, string realTimeAesKey, int &len);

//���ɳ�ʼ�û��б� 
vector<int> getPermuList(int n);

//�������û��б� 
vector<int> getReversePermuList(vector<int> permuList, int n);

//���û�����
void colPermutation(vector<vector<Grid> >& grid, const vector<int>& permuList);
void colPermutation(string &s, const vector<int>& permuList);

//���û�����
void rowPermutation(vector<vector<Grid> >& grid, const vector<int>& permuList);

//SS�ķ�Χ��ѯ�̴߳����� 
void Qthread_SS(StorageServer &SS, ComputingServer CS, ERectangle eQ, phe::Paillier pai); 

//SS�ĵ��ѯ�̴߳����� 
void qthread_SS(StorageServer &SS, ComputingServer CS, PaiEncPoint eq, phe::Paillier pai);  

//���ַ�������ȡ�����ܾ��� 
vector<string> segmentStr(string str, char c);

//���ַ�������ȡ�����ݵ� 
vector<DataPoint> segmentValueStr(unsigned char *data, char c1, char c2);

//��ȡ�����ļ�
vector<Rectangle> readTestFile(char filename[]);
#endif  

