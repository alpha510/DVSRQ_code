#include "DVSQ.h"

using namespace std;

DataOwner::DataOwner()
{
	phe::setrandom();   //置随机数，通过随机数随机生成密钥对 
    phe::Paillier pai;
    pai.keygen(KEY_LEN_BIT);
	this->pubKey = pai.pubkey;
	this->privateKey = pai.prikey;
	this->fixAesKey = "12345678abcdefgh12345678abcdefgh";  //AES固定密钥 
	this->realTimeAesKey = "distributedquerydistributedquery";  //初始实时密钥 
	this->hashKey = "012345678";  //哈希密钥 
}

DataOwner::DataOwner(phe::PaillierKey pubKey, phe::PaillierPrivateKey privateKey, string fixAesKey, string realTimeAesKey, string hashKey)
{
	this->pubKey = pubKey;
	this->privateKey = privateKey;
	this->fixAesKey = fixAesKey;
	this->realTimeAesKey = realTimeAesKey;
	this->hashKey = hashKey;
}

PaiEncPoint DataOwner::getTrapdoor(DataPoint q, phe::Paillier pai)
{
	PaiEncPoint ePoint;
	mpz_t x, y;
	mpz_inits(x, y, ePoint.eX, ePoint.eY, NULL);
	mpz_set_si(x, q.x * 1000000);
	mpz_set_si(y, q.y * 1000000);  
    pai.encrypt(ePoint.eX, x);
    pai.encrypt(ePoint.eY, y);
    mpz_clears(x, y, NULL);
    return ePoint;
}

bool DataOwner::verification(DataPoint q, phe::Paillier pai, vector<vector<int> > colReversePermutations, vector<vector<int> > rowReversePermutations)
{
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		string tempStr = temp.veriInfo[0];
		string hamcStr = temp.veriInfo[1];
		string hmacStr_1 = HmacEncode_rs("md5", hashKey, tempStr);  //重新计算哈希值 
		if (hmacStr_1 != hamcStr)
		{
			cout << "Verification DON'T pass! Subset range is tampered with!" << endl;
			return false;
		}
		vector<string> Infos = segmentStr(tempStr, '|'); 
		ERectangle tempRect, eRect;
		Rectangle rect;
		long x1, x2, y1, y2;
		
		mpz_set_str(tempRect.eMinX, Infos[0].c_str(), 10);  //将密文字符串转换成大整数 
		mpz_set_str(tempRect.eMaxX, Infos[1].c_str(), 10);
		mpz_set_str(tempRect.eMinY, Infos[2].c_str(), 10);
		mpz_set_str(tempRect.eMaxY, Infos[3].c_str(), 10);
		
		pai.decrypt(eRect.eMinX, tempRect.eMinX);  //解密 
		pai.decrypt(eRect.eMaxX, tempRect.eMaxX);
		pai.decrypt(eRect.eMinY, tempRect.eMinY);
		pai.decrypt(eRect.eMaxY, tempRect.eMaxY);
		
		x1 = mpz_get_ui(eRect.eMinX);  //mpz_t 转换成 signed long 
		x2 = mpz_get_ui(eRect.eMaxX);
		y1 = mpz_get_ui(eRect.eMinY);
		y2 = mpz_get_ui(eRect.eMaxY);
		
		rect.minX = x1 * 1.0 / 1000000;  //将整数转换为浮点数 
		rect.maxX = x2 * 1.0 / 1000000;
		rect.minY = y1 * 1.0 / 1000000;
		rect.maxY = y2 * 1.0 / 1000000;
		Rectangle R = rect;
		
		float d1 = (q.x - rect.maxX) * (q.x - rect.minX);
		float d2 = (q.y - rect.maxY) * (q.y - rect.minY);
		
		if(temp.result.empty())  //子集范围不包含查询点 
		{
			if (d1 <= 0 && d2 <= 0) 
			{
				cout << "Verification DON'T pass! Subset " << i << " shouldn't contains the query q!" << endl;
				return false;
			}
		}
		else  //子集范围包含查询点 
		{
			if (d1 > 0 && d2 > 0) 
			{
				cout << "Verification DON'T pass! Subset " << i << " should contains the query q!" << endl;
				return false;
			}
			string s0 = temp.veriInfo[2];
			string hashS0_1 = HmacEncode_rs("md5", hashKey, s0);
			string s1 = temp.veriInfo[4];
			string hashS1_1 = HmacEncode_rs("md5", hashKey, s1);
			if (hashS0_1 != temp.veriInfo[3] || hashS1_1 != temp.veriInfo[5])
			{
				cout << "Verification DON'T pass! Vector s0/s1 is tampered with!" << endl;
				return false;
			}
			colPermutation(s0, colReversePermutations[i]);  //逆置换向量s0和s1 
			colPermutation(s1, rowReversePermutations[i]);
			
			AES rAes(realTimeAesKey);
			string dHash = "";
			rAes.decPaddingCharArr2Str((unsigned char *)temp.veriTable.eHash, temp.veriTable.eHashLen, dHash);
			vector<string> hashSet = segmentStr(dHash, '|');
			
			Grid g = temp.result[0];
			//验证正确性
			string hmacTemp1 = HmacEncode_rs("md5", hashKey, g.eDataPoints);  //--> 1
			string tempStr;
			string xMinStr = mpz_get_str(NULL, 10, g.eRect.eMinX);
			string xMaxStr = mpz_get_str(NULL, 10, g.eRect.eMaxX);
			string yMinStr = mpz_get_str(NULL, 10, g.eRect.eMinY);
			string yMaxStr = mpz_get_str(NULL, 10, g.eRect.eMaxY);
			tempStr += (xMinStr + "|" + xMaxStr + "|" + yMinStr + "|" + yMaxStr + "|" + g.eP + "|"); 
			string hmacTemp2 = HmacEncode_rs("md5", hashKey, tempStr);  //--> 2、3
			string hmacTemp3 = hmacTemp1 + hmacTemp2;  
			string hashValue_1 = HmacEncode_rs("md5", hashKey, hmacTemp3);  //--> 4
			if (hashValue_1 != g.hashValue)
			{
				cout << "Verification DON'T pass! Gird is tampered with!" << endl;
				return false;
			}
			//验证新鲜度 
			AES aes(fixAesKey);
			unsigned char *coo = new unsigned char[g.ePLen];
			int plainTextLen = aes.decCharArr((unsigned char *)g.eP, g.ePLen, coo);
			istringstream iss(reinterpret_cast<char*>(coo));
			iss >> g.p.x;
		    iss.ignore();  //忽略逗号
		    iss >> g.p.y;
			temp.result[0].p.x = g.p.x;
			temp.result[0].p.y = g.p.y;
			delete[] coo;
			if (s0[g.p.x] != '1' || s1[g.p.y] != '1')
			{
				cout << "Verification DON'T pass! Gird_" << g.p.x << "," << g.p.y << " is not the target grid!" << endl;
				return false;
			}
			if (hashSet[g.p.x * s1.length() + g.p.y] != g.hashValue)
			{
				cout << "Verification DON'T pass! Gird in result or TS is tampered with!" << endl;
				return false;
			}
			//验证完整性 
			pai.decrypt(eRect.eMinX, g.eRect.eMinX);  //解密 
			pai.decrypt(eRect.eMaxX, g.eRect.eMaxX);
			pai.decrypt(eRect.eMinY, g.eRect.eMinY);
			pai.decrypt(eRect.eMaxY, g.eRect.eMaxY);
			
			x1 = mpz_get_ui(eRect.eMinX);  //mpz_t 转换成 signed long 
			x2 = mpz_get_ui(eRect.eMaxX);
			y1 = mpz_get_ui(eRect.eMinY);
			y2 = mpz_get_ui(eRect.eMaxY);
			
			rect.minX = x1 * 1.0 / 1000000;  //将整数转换为浮点数 
			rect.maxX = x2 * 1.0 / 1000000;
			rect.minY = y1 * 1.0 / 1000000;
			rect.maxY = y2 * 1.0 / 1000000;
			
			d1 = (q.x - rect.maxX) * (q.x - rect.minX);
			d2 = (q.y - rect.maxY) * (q.y - rect.minY);
			if (d1 > 0 && d2 > 0) 
			{
				cout << "Verification DON'T pass! Gird_" << g.p.x << "," << g.p.y << " should contains the query q!" << endl;
				return false;
			}
		}		
	}
	return true;
}

void DataOwner::resultDecrypt()
{
	AES aes(fixAesKey);
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		if (!temp.result.empty())
		{
			Grid g = temp.result[0];
			unsigned char *plainText = new unsigned char [g.eDLen];
			int PlainTextLen = aes.decCharArr((unsigned char *)g.eDataPoints, g.eDLen, plainText);
//			cout << "after decrypt:" << plainText << endl; 
			FinalResult[i].result[0].dataPoints = segmentValueStr(plainText, ',', '|');
			delete[] plainText; 
		}
	}
} 

void DataOwner::insertPoint(DataPoint p)
{
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		if (!temp.result.empty())
		{
			Grid g = temp.result[0];
			for (int j = 0; j < g.dataPoints.size(); j++)  //判断点p是否存在于该网格中 
			{
				if (p.x == g.dataPoints[j].x && p.y == g.dataPoints[j].y)
				{
					cout << "Invalid insertion! Point P exists in this Grid!" << endl;
					return;
				}
			}
			//如果点p不在网格中，判断点p是否在网格的范围内 
			if (p.x >= g.rect.minX && p.x <= g.rect.maxX && p.y >= g.rect.minY && p.y <= g.rect.maxY)
			{
				for (int j = 0; j < g.dataPoints.size(); j++)
				{
					if (fabs(g.dataPoints[j].x - 0) < FLT_EPSILON && fabs(g.dataPoints[j].y - 0) < FLT_EPSILON)
					{
						FinalResult[i].result[0].dataPoints[j].x = p.x;
						FinalResult[i].result[0].dataPoints[j].y = p.y;
//						cout << "Insertion success!" << endl;
						return;
					}
				}
				cout << "Insertion failed! The space of Grid is not enough!" << endl;
				return;
			}
			//如果点p不在网格的范围内 
			else
			{
				cout << "Insertion failed! Point p is not in the range of the Grid!" << endl; 
				cout << p.x << ", " << p.y << endl;
				return;
			}
		}
	}
}  

void DataOwner::deletePoint(DataPoint p)
{
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		if (!temp.result.empty())
		{
			Grid g = temp.result[0];
			for (int j = 0; j < g.dataPoints.size(); j++)  //判断点p是否存在于该网格中 
			{
				if (p.x == g.dataPoints[j].x && p.y == g.dataPoints[j].y)
				{
					FinalResult[i].result[0].dataPoints[j].x = 0.0;  //将该点替换为（0.0, 0.0） 
					FinalResult[i].result[0].dataPoints[j].x = 0.0;
					cout << "Delete success!" << endl;
					return;
				}
			}
			//如果点p不在网格中 
			cout << "Invaild delete! Point p is not in the Grid!" << endl; 
			return;
		}
	}
} 

int DataOwner::updateGrid()  
{
	int sID;
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult tmp = FinalResult[i];
		if (!tmp.result.empty())
		{
			Grid g = tmp.result[0];
			//重新加密（AES）小网格数据 
			AES aes(fixAesKey);
			char buf[409600] = {'\0'};
		    char temp[10] = {'\0'};
		    int len;
		    
		    int w = g.dataPoints.size();
			for (int l = 0; l < w; l++)
			{
				DataPoint point = g.dataPoints[l];
				if (fabs(point.x - 0) < FLT_EPSILON && fabs(point.y - 0) < FLT_EPSILON)
					strcat(buf, "0.000000,0.000000");
				else
				{
					gcvt(point.x, 6, temp);  //gcvt：float 转 string 
					strcat(buf, temp);
					strcat(buf, ",");  //分隔符"|"分隔一个点的x、y坐标 
					gcvt(point.y, 6, temp);
					strcat(buf, temp);
				}	
				strcat(buf, "|");  //分隔符"|"分隔两个数据点  
			} 
			len = strlen(buf);
//			cout << "len = " << len << endl;
			if (len == 0)
			{
				cerr << "The length of dataPoint should be greater than 0" << endl; 
				return -1;
			}
			len = ((len + 1) / 16 + 2) * 16;
			free(g.eDataPoints);  //释放掉之前指向的空间  
			g.eDataPoints = (char *)malloc(sizeof(char) * len);  //指针指向新的空间 
			g.eDLen = aes.encCharArr((unsigned char *)buf, strlen(buf) + 1, (unsigned char *)g.eDataPoints);
			
			//重新计算哈希值 
			string hmacTemp1 = HmacEncode_rs("md5", hashKey, g.eDataPoints);  //--> 1
			string tempStr;
			string xMinStr = mpz_get_str(NULL, 10, g.eRect.eMinX);
			string xMaxStr = mpz_get_str(NULL, 10, g.eRect.eMaxX);
			string yMinStr = mpz_get_str(NULL, 10, g.eRect.eMinY);
			string yMaxStr = mpz_get_str(NULL, 10, g.eRect.eMaxY);
			tempStr += (xMinStr + "|" + xMaxStr + "|" + yMinStr + "|" + yMaxStr + "|" + g.eP + "|"); 
			string hmacTemp2 = HmacEncode_rs("md5", hashKey, tempStr);  //--> 2、3
			string hmacTemp3 = hmacTemp1 + hmacTemp2;  
			g.hashValue = HmacEncode_rs("md5", hashKey, hmacTemp3);  //--> 4
			//小网格内容更新 
			FinalResult[i].result[0] = g;
			sID = i;
			break;
		}
	}
	return sID;
}

vector<VeriTable> DataOwner::updateVeriTable(int sID)  
{
	vector<VeriTable> vTable;
	vector<string> dHashs;
 	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		string dHash = "";
		int len = 0;
		AES rAes1(realTimeAesKey);
		//用旧的实时密钥解密 
		rAes1.decPaddingCharArr2Str((unsigned char *)temp.veriTable.eHash, temp.veriTable.eHashLen, dHash);
		if (i == sID)
		{
			Grid g = temp.result[0];
			int px = temp.veriInfo[2].length();
			int py = temp.veriInfo[4].length();
			len = g.hashValue.length();
			int start = (g.p.x * py + g.p.y) * (len + 1);
			for (int j = 0; j < len; j++)
				dHash[start + j] = g.hashValue[j];  //内容更新 
		}
		dHashs.push_back(dHash);
	}
	updateRealTimeAesKey();  //更新实时密钥 
	AES rAes2(realTimeAesKey);
	for (int i = 0; i <FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		string dHash = dHashs[i];
		temp.veriTable.eHashLen = ((dHash.length() + 1) / 16 + 2) * 16;
		free(temp.veriTable.eHash);  //释放掉之前的空间 
	    temp.veriTable.eHash = (char*)malloc(sizeof(char) * temp.veriTable.eHashLen);  //重新指向新的空间 
	    //用新的实时密钥加密  
	    rAes2.encPaddingStr(dHash, (unsigned char *)temp.veriTable.eHash, temp.veriTable.eHashLen);
	    vTable.push_back(temp.veriTable); 
	}
	return vTable;
}

void DataOwner::updateRealTimeAesKey()
{
	int len = realTimeAesKey.length();
	for (int i = 0; i < len; i++)
	{
		if (rand() % 2 == 0)
			realTimeAesKey[i] += 1;
		else 
			realTimeAesKey[i] -= 1;
		if (realTimeAesKey[i] < 'a' || realTimeAesKey[i] >'z')
			realTimeAesKey[i] = rand() % 26 + 'a';
	}
}

Coordinate DataOwner::relocationGrid(int sID, vector<int> colPermuList, vector<int> rowPermuList)
{
	Grid g = FinalResult[sID].result[0];
	int px = colPermuList.size();
	for (int i = 0; i < px; i++)
	{
		if (colPermuList[i] == g.p.x)
		{
			g.p.x = i;
			break;
		}
	}
	int py = rowPermuList.size();
	for (int i = 0; i < py; i++)
	{
		if (rowPermuList[i] == g.p.y)
		{
			g.p.y = i;
			break;
		}
	}
	return g.p;
}

DataOwner::~DataOwner()
{
 
}

DataUser::DataUser()
{
	
}

DataUser::DataUser(phe::PaillierKey pubKey, phe::PaillierPrivateKey privateKey, string fixAesKey, string realTimeAesKey, string hashKey)
{
	this->pubKey = pubKey;
	this->privateKey = privateKey;
	this->fixAesKey = fixAesKey;
	this->realTimeAesKey = realTimeAesKey;
	this->hashKey = hashKey;
}

ERectangle DataUser::getTrapdoor(Rectangle Q, phe::Paillier pai)
{
	ERectangle eRect;
	mpz_t x1, x2, y1, y2;
	mpz_inits(x1, x2, y1, y2, NULL);
	mpz_set_si(x1, Q.minX * 1000000);
	mpz_set_si(x2, Q.maxX * 1000000);
	mpz_set_si(y1, Q.minY * 1000000);
	mpz_set_si(y2, Q.maxY * 1000000);  
    pai.encrypt(eRect.eMinX, x1);
    pai.encrypt(eRect.eMaxX, x2);
    pai.encrypt(eRect.eMinY, y1);
    pai.encrypt(eRect.eMaxY, y2);
    mpz_clears(x1, x2, y1, y2, NULL);
    return eRect;
}

bool DataUser::verification(Rectangle Q, phe::Paillier pai, vector<vector<int> > colReversePermutations, vector<vector<int> > rowReversePermutations)
{
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		string tempStr = temp.veriInfo[0];  //子集范围组成的字符串 
		string hamcStr = temp.veriInfo[1];  //子集范围字符串的哈希值 
		string hmacStr_1 = HmacEncode_rs("md5", hashKey, tempStr);  //重新计算哈希值 
		if (hmacStr_1 != hamcStr)
		{
			cout << "Verification DON'T pass! Subset range is tampered with!" << endl;
			return false;
		}
		vector<string> Infos = segmentStr(tempStr, '|'); 
		ERectangle tempRect, eRect;
		Rectangle rect;
		long x1, x2, y1, y2;
		
		mpz_set_str(tempRect.eMinX, Infos[0].c_str(), 10);  //将密文字符串转换成大整数 
		mpz_set_str(tempRect.eMaxX, Infos[1].c_str(), 10);
		mpz_set_str(tempRect.eMinY, Infos[2].c_str(), 10);
		mpz_set_str(tempRect.eMaxY, Infos[3].c_str(), 10);
		
		pai.decrypt(eRect.eMinX, tempRect.eMinX);  //解密 
		pai.decrypt(eRect.eMaxX, tempRect.eMaxX);
		pai.decrypt(eRect.eMinY, tempRect.eMinY);
		pai.decrypt(eRect.eMaxY, tempRect.eMaxY);
		
		x1 = mpz_get_ui(eRect.eMinX);  //mpz_t 转换成 signed long 
		x2 = mpz_get_ui(eRect.eMaxX);
		y1 = mpz_get_ui(eRect.eMinY);
		y2 = mpz_get_ui(eRect.eMaxY);
		
		rect.minX = x1 * 1.0 / 1000000;  //将整数转换为浮点数 
		rect.maxX = x2 * 1.0 / 1000000;
		rect.minY = y1 * 1.0 / 1000000;
		rect.maxY = y2 * 1.0 / 1000000;
		Rectangle R = rect;  //R：子集范围的明文 
		
		float d1 = (Q.minX - rect.maxX) * (Q.maxX - rect.minX);
		float d2 = (Q.minY - rect.maxY) * (Q.maxY - rect.minY);
		
		if(temp.result.empty())  //子集范围与查询范围应不相交 
		{
			if (d1 <= 0 && d2 <= 0)  //代表相交 
			{
				cout << "Verification DON'T pass! Subset " << i << " shouldn't intersects the query Q!" << endl;
				return false;
			}
		}
		else  //子集范围与查询范围应该相交 
		{
			if (d1 > 0 && d2 > 0)  //代表不相交 
			{    
				cout << "Verification DON'T pass! Subset " << i << " should intersects the query Q!" << endl;
				return false;
			}
			string s0 = temp.veriInfo[2];
			string hashS0_1 = HmacEncode_rs("md5", hashKey, s0);
			string s1 = temp.veriInfo[4];
			string hashS1_1 = HmacEncode_rs("md5", hashKey, s1);
			if (hashS0_1 != temp.veriInfo[3] || hashS1_1 != temp.veriInfo[5])
			{
				cout << "Verification DON'T pass! Vector s0/s1 is tampered with!" << endl;
				return false;
			}
			colPermutation(s0, colReversePermutations[i]);  //逆置换向量s0和s1 
			colPermutation(s1, rowReversePermutations[i]);
			
			AES rAes(realTimeAesKey);
			string dHash = "";
			rAes.decPaddingCharArr2Str((unsigned char *)temp.veriTable.eHash, temp.veriTable.eHashLen, dHash);
			vector<string> hashSet = segmentStr(dHash, '|');
						
			for (int j = 0; j < temp.result.size(); j++)
			{
				Grid g = temp.result[j];
				//验证正确性
				string hmacTemp1 = HmacEncode_rs("md5", hashKey, g.eDataPoints);  //--> 1
				string tempStr;
				string xMinStr = mpz_get_str(NULL, 10, g.eRect.eMinX);
				string xMaxStr = mpz_get_str(NULL, 10, g.eRect.eMaxX);
				string yMinStr = mpz_get_str(NULL, 10, g.eRect.eMinY);
				string yMaxStr = mpz_get_str(NULL, 10, g.eRect.eMaxY);
				tempStr += (xMinStr + "|" + xMaxStr + "|" + yMinStr + "|" + yMaxStr + "|" + g.eP + "|"); 
				string hmacTemp2 = HmacEncode_rs("md5", hashKey, tempStr);  //--> 2、3
				string hmacTemp3 = hmacTemp1 + hmacTemp2;  
				string hashValue_1 = HmacEncode_rs("md5", hashKey, hmacTemp3);  //--> 4
				if (hashValue_1 != g.hashValue)
				{
					cout << "Verification DON'T pass! Gird is tampered with!" << endl;
					return false;
				}
				//验证新鲜度 
				AES aes(fixAesKey);
				unsigned char *coo = new unsigned char[g.ePLen];
				int plainTextLen = aes.decCharArr((unsigned char *)g.eP, g.ePLen, coo);
				istringstream iss(reinterpret_cast<char*>(coo));
				iss >> g.p.x;
			    iss.ignore();  //忽略逗号
			    iss >> g.p.y;
				temp.result[j].p.x = g.p.x;
				temp.result[j].p.y = g.p.y;
				delete[] coo; 
				if (s0[g.p.x] != '1' || s1[g.p.y] != '1')
				{
					cout << "Verification DON'T pass! Gird_" << g.p.x << "," << g.p.y << " is not the target grid!" << endl;
					return false;
				}
				if (hashSet[g.p.x * s1.length() + g.p.y] != g.hashValue)
				{
					cout << "Verification DON'T pass! Gird in result or TS is tampered with!" << endl;
					return false;
				}
				//验证完整性 
//				pai.decrypt(eRect.eMinX, g.eRect.eMinX);  //解密 
//				pai.decrypt(eRect.eMaxX, g.eRect.eMaxX);
//				pai.decrypt(eRect.eMinY, g.eRect.eMinY);
//				pai.decrypt(eRect.eMaxY, g.eRect.eMaxY);
//				
//				x1 = mpz_get_ui(eRect.eMinX);  //mpz_t 转换成 signed long 
//				x2 = mpz_get_ui(eRect.eMaxX);
//				y1 = mpz_get_ui(eRect.eMinY);
//				y2 = mpz_get_ui(eRect.eMaxY);
//				
//				rect.minX = x1 * 1.0 / 1000000;  //将整数转换为浮点数 
//				rect.maxX = x2 * 1.0 / 1000000;
//				rect.minY = y1 * 1.0 / 1000000;
//				rect.maxY = y2 * 1.0 / 1000000;
//				temp.result[j].rect = rect;
//				
//				d1 = (Q.minX - rect.maxX) * (Q.maxX - rect.minX);
//				d2 = (Q.minY - rect.maxY) * (Q.maxY - rect.minY);
//				if (d1 > 0 && d2 > 0) 
//				{
//					cout << "Verification DON'T pass! Gird_" << g.p.x << "," << g.p.y << " should intersects the query Q!" << endl;
//					return false;
//				}
			}
			int minX, minY, maxX, maxY;
			minX = s0.length();
			minY = s1.length();
			maxX = 0;
			maxY = 0;
			for (int j = 0; j < temp.result.size(); j++)
			{
				Grid g = temp.result[j];
				if (minX > g.p.x)  minX = g.p.x;
				if (minY > g.p.y)  minY = g.p.y;
				if (maxX < g.p.x)  maxX = g.p.x;
				if (maxY < g.p.y)  maxY = g.p.y;
			}
			int num = (maxX - minX + 1) * (maxY - minY + 1); 
			if (num != temp.result.size())
			{
				cout << "Verification DON'T pass! The number of gird in result of subset "<< i << " is not enough!" << endl;
//				return false;
			}
			for (int j = 0; j < temp.result.size(); j++)  //rect:由小网格组成的包含查询范围的矩形 
			{
				Grid g = temp.result[j];
				if (g.p.x == minX && g.p.y == minY)
				{
					pai.decrypt(eRect.eMinX, g.eRect.eMinX);  //解密 
					pai.decrypt(eRect.eMinY, g.eRect.eMinY);
					
					x1 = mpz_get_ui(eRect.eMinX);  //mpz_t 转换成 signed long 
					y1 = mpz_get_ui(eRect.eMinY);
					
					rect.minX = x1 * 1.0 / 1000000;  //将整数转换为浮点数 
					rect.minY = y1 * 1.0 / 1000000;
//					rect.minX = g.rect.minX;
//					rect.minY = g.rect.minY;
				}
				if (g.p.x == maxX && g.p.y == maxY)
				{ 
					pai.decrypt(eRect.eMaxX, g.eRect.eMaxX);  //解密 
					pai.decrypt(eRect.eMaxY, g.eRect.eMaxY);
					 
					x2 = mpz_get_ui(eRect.eMaxX);  //mpz_t 转换成 signed long
					y2 = mpz_get_ui(eRect.eMaxY);
					  
					rect.maxX = x2 * 1.0 / 1000000;  //将整数转换为浮点数
					rect.maxY = y2 * 1.0 / 1000000;
//					rect.maxX = g.rect.maxX;
//					rect.maxY = g.rect.maxY;
				}
			}
			vector<Rectangle> rects;  //rects:保存上述rect的补 
			if (rect.minX > R.minX)
			{
				Rectangle tmpR;
				tmpR.minX = R.minX;
				tmpR.maxX = rect.minX;
				tmpR.minY = R.minY;
				tmpR.maxY = R.maxY;
				rects.push_back(tmpR);
			}
			if (rect.maxX < R.maxX)
			{
				Rectangle tmpR;
				tmpR.minX = rect.maxX;
				tmpR.maxX = R.maxX;
				tmpR.minY = R.minY;
				tmpR.maxY = R.maxY;
				rects.push_back(tmpR);
			} 
			if (rect.minY > R.minY)
			{
				Rectangle tmpR;
				tmpR.minX = R.minX;
				tmpR.maxX = R.maxX;
				tmpR.minY = R.minY;
				tmpR.maxY = rect.minY;
				rects.push_back(tmpR);
			}
			if (rect.maxY < R.maxY)
			{
				Rectangle tmpR;
				tmpR.minX = R.minX;
				tmpR.maxX = R.maxX;
				tmpR.minY = rect.maxY;
				tmpR.maxY = R.maxY;
				rects.push_back(tmpR);
			}
			for (int j = 0; j < rects.size(); j++)
			{
				Rectangle tmpR = rects[j];
				d1 = (tmpR.minX - Q.maxX) * (tmpR.maxX - Q.minX);
				d2 = (tmpR.minY - Q.maxY) * (tmpR.maxY - Q.minY);
				if (d1 <= 0 && d2 <= 0)
				{
					cout << "Verification DON'T pass! The range not returned intersects the query Q!" << endl;
					return false;
				}
			}
		}
	}
	return true;
}

void DataUser::resultDecrypt()
{
	AES aes(fixAesKey);
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		if (!temp.result.empty())
		{
			for (int j = 0; j < temp.result.size(); j++)
			{
				Grid g = temp.result[j];
				unsigned char *plainText = new unsigned char [g.eDLen];
				int PlainTextLen = aes.decCharArr((unsigned char *)g.eDataPoints, g.eDLen, plainText);
				FinalResult[i].result[j].dataPoints = segmentValueStr(plainText, ',', '|');
				delete[] plainText;
			}
		}
	}
}

pair<int, int> DataUser::resultRefine(Rectangle Q)
{
	pair<int, int> tmp;
	tmp.first = 0;
	tmp.second = 0;
	for (int i = 0; i < FinalResult.size(); i++)
	{
		SubResult temp = FinalResult[i];
		if (!temp.result.empty())
		{
			for (int j = 0; j < temp.result.size(); j++)
			{
				Grid g = temp.result[j];
				for (int k = 0; k < g.dataPoints.size(); k++)
				{
					DataPoint p = g.dataPoints[k];
					if (p.x >= Q.minX && p.x <= Q.maxX && p.y >= Q.minY && p.y <= Q.maxY)  tmp.first++;
					else  tmp.second++;
				}
			}
		}
	}
	return tmp;
} 

DataUser::~DataUser()
{
	
}

TransmissionServer::TransmissionServer()
{
	
} 

TransmissionServer::TransmissionServer(vector<VeriTable> veriTable)
{
	this->veriTable = veriTable;
}

TransmissionServer::~TransmissionServer()
{
	for (int i = 0; i < veriTable.size(); i++)
	{
		free(veriTable[i].eHash);
		veriTable[i].eHash = NULL;
	}
//	cout << "The memory of TS has been freed and the pointer has been set NULL!" << endl;
}

void TransmissionServer::receiveResult(vector<Grid> result, vector<string> veriInfo)
{
	SubResult temp;
	temp.result = result;
	temp.veriInfo = veriInfo;
	this->FinalResult.push_back(temp); 
} 

void TransmissionServer::summaryResult(int signal)
{
	if (signal == 0)
	{
		for (int i = 0; i < FinalResult.size(); i++)
		{
			VeriTable tempVTable;
			tempVTable.serverID = i;
			tempVTable.eHashLen = 0;
			if (!FinalResult[i].result.empty())  //结果集不为空，复制eHash，结果集为空，eHash也为空 
			{
				tempVTable.eHash = veriTable[i].eHash;
				tempVTable.eHashLen = veriTable[i].eHashLen;
			}
			else
				tempVTable.eHash = NULL;
			FinalResult[i].veriTable = tempVTable;
		}
	}
	if (signal == 1)
	{
		for (int i = 0; i < FinalResult.size(); i++)
			FinalResult[i].veriTable = veriTable[i];
	}
}

void TransmissionServer::setEmpty()
{
	vector<SubResult> emptySet;
	FinalResult.swap(emptySet);
} 

ComputingServer::ComputingServer()
{
	
}

ComputingServer::ComputingServer(phe::PaillierKey pubkey, phe::PaillierPrivateKey privateKey, string hashKey)
{
	this->pubkey = pubkey;
	this->privateKey = privateKey;
	this->hashKey = hashKey;
}

ComputingServer::~ComputingServer()
{
	
}

StorageServer::StorageServer()
{
	
}

StorageServer::StorageServer(ERectangle eRect, vector<vector<Grid> > gridSet)
{
	this->eRect = eRect;
	this->gridSet = gridSet;
}

int StorageServer::genRandom()
{
	random_device rd;  //使用随机设备作为种子
	mt19937 gen(rd());  //使用随机设备生成的种子初始化伪随机数生成器 
	uniform_int_distribution<int> distribution(1, 10000);  //定义要生成的随机整数的范围 
	int randomNum = distribution(gen);  //生成随机整数 
	return randomNum;
}

void StorageServer::setEmpty()
{
	vector<Grid> emptyResult;
	vector<string> emptyVeriInfo;
	result.swap(emptyResult);
	veriInfo.swap(emptyVeriInfo); 
}

StorageServer::~StorageServer()
{
	for (int i = 0; i < gridSet.size(); i++)
	{
		for (int j = 0; j < gridSet[0].size(); j++)
		{
			free(gridSet[i][j].eDataPoints);
			gridSet[i][j].eDataPoints = NULL;
			free(gridSet[i][j].eP);
			gridSet[i][j].eP = NULL;
		}
	}
//	cout << "The memory of SS has been freed and the pointer has been set NULL!" << endl;
}

//读取文件
vector<DataPoint> readFile(char filename[]) 
{
    vector<DataPoint> dataPoints;
    ifstream inputFile(filename);
    if (!inputFile.is_open()) 
	{
        cerr << "Error opening file: " << filename << endl;
        return dataPoints; // 返回空的数据结构表示出错 
    }
    float x, y;
    while (inputFile >> x >> y) 
	{
        DataPoint point = {x, y};
        dataPoints.push_back(point);
    }
    inputFile.close();
    return dataPoints;
}

//获取数据集所在大矩形 
Rectangle getDataRange(vector<DataPoint> dataPoints)
{
	Rectangle rect;
	//初始化矩形的边界值 
    rect.minX = numeric_limits<float>::max();
    rect.maxX = numeric_limits<float>::min();
    rect.minY = numeric_limits<float>::max();
    rect.maxY = numeric_limits<float>::min();
    
    for (size_t i = 0; i < dataPoints.size(); i++)
    {
    	// 更新矩形的边界值
        if (dataPoints[i].x < rect.minX) rect.minX = (int)dataPoints[i].x * 1.0;
        if (dataPoints[i].x > rect.maxX) rect.maxX = (int)dataPoints[i].x + 1.0;
        if (dataPoints[i].y < rect.minY) rect.minY = (int)dataPoints[i].y * 1.0;
        if (dataPoints[i].y > rect.maxY) rect.maxY = (int)dataPoints[i].y + 1.0;
	}
	return rect;
}

//给定Server的数量，获取大子集划分情况 
pair<int, int> getClosestFactor(int num)
{
	pair<int, int> result;
    if (num <= 1) 
	{
        cerr << "The number of servers should be a positive integer greater than 1." << endl;
        return result;
    }
    for (int i = (int)sqrt(num); i >= 1; i--) 
	{
        if (num % i == 0) 
		{
            int factor1 = i;        //Y轴划分段数 
            int factor2 = num / i;  //X轴划分段数 
            result = {factor1, factor2};  //factor1 <= factor2
            break;
        }
    }
    return result;
}

//为每个Server划分子集 
void partition(Rectangle rect, pair<int, int> factors,  Server serv[SERVER_NUM], vector<DataPoint> dataPoints)
{
	//计算步长 
	float intervalX = (rect.maxX - rect.minX) / (factors.second * 1.0);
	float intervalY = (rect.maxY - rect.minY) / (factors.first * 1.0);	
	
	int k = 0;
	Rectangle tempRect;
	for (int i = 0; i < factors.second; i++)     //X轴  
	{
		for (int j = 0; j < factors.first; j++)  //Y轴 
		{
			tempRect.minX = rect.minX + intervalX * i;
			tempRect.minY = rect.minY + intervalY * j;
			tempRect.maxX = tempRect.minX + intervalX;
			tempRect.maxY = tempRect.minY + intervalY;
			serv[k].rect = tempRect;
			for (int l = 0; l < dataPoints.size(); l++) 
			{
				DataPoint point = dataPoints[l];
				if (point.x >= serv[k].rect.minX && point.x < serv[k].rect.maxX 
				 && point.y >= serv[k].rect.minY && point.y < serv[k].rect.maxY)
				{
				 	serv[k].dataPoints.push_back(point);
				}
			}
			k++;
		}	
	}
	return;	
}

//为每个子集划分小网格 且 求出最大的网格宽度 
int divideGrid(Server &serv)
{
	Rectangle rect = serv.rect;
	vector<int> X(pow(2, LAMBDA), 0);
	vector<int> Y(pow(2, LAMBDA), 0); 
	float omigaX = (rect.maxX - rect.minX) * pow(2, LAMBDA * (-1));
	float omigaY = (rect.maxY - rect.minY) * pow(2, LAMBDA * (-1));
	//X轴划分网格 
	for (int i = 0; i < serv.dataPoints.size(); i++)
	{
		DataPoint point = serv.dataPoints[i];
		int pos = (int)((point.x - rect.minX) / omigaX);
		X[pos]++;
	}	
	int widthX = *max_element(X.begin(), X.end());
	vector<int> mergeX;
	for (int j = 0; j < X.size(); )
	{
		int sum = 0;
		int count = 0;
		while (sum <= widthX)
		{
			sum += X[j];
			j++;
			count++;
		}
		mergeX.push_back(count-1);
		j--;
	}
	serv.Px = mergeX.size();
	
	//Y轴划分网格 
	for (int i = 0; i < serv.dataPoints.size(); i++)
	{
		DataPoint point = serv.dataPoints[i];
		int pos = (int)((point.y - rect.minY) / omigaY);
		Y[pos]++;
	}
	int widthY = *max_element(Y.begin(), Y.end());
	vector<int> mergeY;
	for (int j = 0; j < Y.size(); )
	{
		int sum = 0;
		int count = 0;
		while (sum <= widthY)
		{
			sum += Y[j];
			j++;
			count++;
		}
		mergeY.push_back(count-1);
		j--;
	}
	serv.Py = mergeY.size();
	
	vector<int> tempX(mergeX.size(), 0);
	vector<int> tempY(mergeY.size(), 0);
	tempX[0] = mergeX[0];
	tempY[0] = mergeY[0];
	for (int i = 1; i < mergeX.size(); i++)
		tempX[i] = tempX[i-1] + mergeX[i];
	for (int i = 1; i < mergeY.size(); i++)
		tempY[i] = tempY[i-1] + mergeY[i];
	
	//计算最小步长	
	float intervalX = (rect.maxX - rect.minX) / X.size();
	float intervalY = (rect.maxY - rect.minY) / Y.size();
	
	int maxWidth = 0;
	for (int i = 0; i < mergeX.size(); i++)
	{
		vector<Grid> gi;
		for (int j = 0; j < mergeY.size(); j++)
		{
			Grid gij;
			//记录网格的矩形边界 
			gij.rect.maxX = serv.rect.minX + intervalX * tempX[i];
			gij.rect.minX = gij.rect.maxX - intervalX * mergeX[i];
			gij.rect.maxY = serv.rect.minY + intervalY * tempY[j];
			gij.rect.minY = gij.rect.maxY - intervalY * mergeY[j];
			
			for (int l = 0; l < serv.dataPoints.size(); l++)
			{
				DataPoint point = serv.dataPoints[l];
				if (point.x >= gij.rect.minX && point.x < gij.rect.maxX 
				 && point.y >= gij.rect.minY && point.y < gij.rect.maxY)
				{
				 	gij.dataPoints.push_back(point);
				}
			}
			//找到最大网格包含的数据点个数 
			if (maxWidth < gij.dataPoints.size()) maxWidth = gij.dataPoints.size();
			//记录网格坐标 
			gij.p.x = i;
			gij.p.y = j;
//			gij.tag = rand() % 10;
			gi.push_back(gij);
		}
		serv.gridSet.push_back(gi); 
	}
	vector<DataPoint> emptyset;
	serv.dataPoints.swap(emptyset);  //释放空间 
	cout << "Px = " << serv.Px << "	Py = " << serv.Py << endl;
	return maxWidth;
}

//添加假点 
void addFakePoints(int maxWidth, Server &serv, float theta)
{
	int realWidth = (int)(maxWidth + maxWidth * theta);
	for (int i = 0; i < serv.Px; i++)
	{
		for (int j = 0; j < serv.Py; j++)
		{
			while (serv.gridSet[i][j].dataPoints.size() < realWidth)
			{
				DataPoint fakePoint = {0.0, 0.0};
				serv.gridSet[i][j].dataPoints.push_back(fakePoint);
			}
		}
	}
	return;
}

//数据加密 
void dataEncryption(Server &serv, phe::Paillier pai, string fixAesKey)
{
	mpz_t x1, x2, y1, y2;
	AES aes(fixAesKey);
	
	//子集矩形边界（paillier）加密 
	mpz_inits(x1, x2, y1, y2, NULL);
	
	mpz_set_si(x1, serv.rect.minX * 1000000);
	mpz_set_si(x2, serv.rect.maxX * 1000000);
    mpz_set_si(y1, serv.rect.minY * 1000000);
    mpz_set_si(y2, serv.rect.maxY * 1000000);
        
    pai.encrypt(serv.eRect.eMinX, x1);
    pai.encrypt(serv.eRect.eMaxX, x2);
    pai.encrypt(serv.eRect.eMinY, y1);
    pai.encrypt(serv.eRect.eMaxY, y2);
    	 
	for (int i = 0; i < serv.Px; i++) 
	{
		for (int j = 0; j < serv.Py; j++)  
		{
			//小网格矩形边界（paillier）加密 
			mpz_set_si(x1, serv.gridSet[i][j].rect.minX * 1000000);
			mpz_set_si(x2, serv.gridSet[i][j].rect.maxX * 1000000);
		    mpz_set_si(y1, serv.gridSet[i][j].rect.minY * 1000000);
		    mpz_set_si(y2, serv.gridSet[i][j].rect.maxY * 1000000);
		    
		    pai.encrypt(serv.gridSet[i][j].eRect.eMinX, x1);
		    pai.encrypt(serv.gridSet[i][j].eRect.eMaxX, x2);
		    pai.encrypt(serv.gridSet[i][j].eRect.eMinY, y1);
		    pai.encrypt(serv.gridSet[i][j].eRect.eMaxY, y2);
		    
		    char buf[409600] = {'\0'};  //开辟空间取决于要加密的字符串长度，10240目前适用于NE数据集 
		    char temp[10] = {'\0'};
		    int len;
		    
		    //小网格坐标（AES）加密 
		    sprintf(temp, "%d", serv.gridSet[i][j].p.x);  //sprintf：int 转 string 
		    strcat(buf, temp);
			strcat(buf, ",");
			sprintf(temp, "%d", serv.gridSet[i][j].p.y);
			strcat(buf, temp);
			len = strlen(buf);
			if (len == 0)
			{
				cerr << "The length of coordinate should be greater than 0" << endl; 
				return;
			}
			len = ((len + 1) / 16 + 2) * 16;
			serv.gridSet[i][j].eP = (char *)malloc(sizeof(char) * len);
			serv.gridSet[i][j].ePLen = aes.encCharArr((unsigned char *)buf, strlen(buf) + 1, (unsigned char *)serv.gridSet[i][j].eP);
			
			//小网格数据（AES）加密 
			int w = serv.gridSet[i][j].dataPoints.size();
			strcpy(buf, "");
			for (int l = 0; l < w; l++)
			{
				DataPoint point = serv.gridSet[i][j].dataPoints[l];
				if (fabs(point.x - 0) < FLT_EPSILON && fabs(point.y - 0) < FLT_EPSILON)
					strcat(buf, "0.000000,0.000000");
				else
				{
					gcvt(point.x, 6, temp);  //gcvt：float 转 string 
					strcat(buf, temp);
					strcat(buf, ",");  //分隔符"|"分隔一个点的x、y坐标 
					gcvt(point.y, 6, temp);
					strcat(buf, temp);
				}	
				strcat(buf, "|");  //分隔符"|"分隔两个数据点  
			} 
			len = strlen(buf);
			if (len == 0)
			{
				cerr << "The length of dataPoint should be greater than 0" << endl; 
				return;
			}
			len = ((len + 1) / 16 + 2) * 16;  
			serv.gridSet[i][j].eDataPoints = (char *)malloc(sizeof(char) * len);
			serv.gridSet[i][j].eDLen = aes.encCharArr((unsigned char *)buf, strlen(buf) + 1, (unsigned char *)serv.gridSet[i][j].eDataPoints);
		}
	}
	mpz_clears(x1, x2, y1, y2, NULL);
	return;
}

//计算哈希值 
void hashSign(Server &serv, string hashKey)
{
	for ( int i = 0; i < serv.Px; i++)
	{
		for (int j = 0; j < serv.Py; j++)
		{
			string hmacTemp1 = HmacEncode_rs("md5", hashKey, serv.gridSet[i][j].eDataPoints);  //--> 1
			string tempStr;
			string xMinStr = mpz_get_str(NULL, 10, serv.gridSet[i][j].eRect.eMinX);
			string xMaxStr = mpz_get_str(NULL, 10, serv.gridSet[i][j].eRect.eMaxX);
			string yMinStr = mpz_get_str(NULL, 10, serv.gridSet[i][j].eRect.eMinY);
			string yMaxStr = mpz_get_str(NULL, 10, serv.gridSet[i][j].eRect.eMaxY);
			tempStr += (xMinStr + "|" + xMaxStr + "|" + yMinStr + "|" + yMaxStr + "|" + serv.gridSet[i][j].eP + "|"); 
			string hmacTemp2 = HmacEncode_rs("md5", hashKey, tempStr);  //--> 2、3
			string hmacTemp3 = hmacTemp1 + hmacTemp2;  
			serv.gridSet[i][j].hashValue = HmacEncode_rs("md5", hashKey, hmacTemp3);  //--> 4
		}
	}
	return; 
}

//生成验证信息表 
char* geneVeriTable(Server serv, string realTimeAesKey, int &len)
{
	AES rAes(realTimeAesKey);
	string str = "";
	for (int i = 0; i < serv.Px; i++)
	{
		for (int j = 0; j < serv.Py; j++)
		{
			str += serv.gridSet[i][j].hashValue;
			str += "|";  //分隔两个哈希值 
		}
	}
	len = ((str.length() + 1) / 16 + 2) * 16;
    char *ciphertext = (char*)malloc(sizeof(char) * len);
    rAes.encPaddingStr(str, (unsigned char *)ciphertext, len);
    return ciphertext;
}

//生成初始置换列表 
vector<int> getPermuList(int n)
{
	vector<int> permuList(n);
	for (int i = 0; i < n; i++)
	{
		permuList[i] = i;
	}
	random_device rd;
    mt19937 g(rd());
    uniform_int_distribution<int> distribution(0, n-1);
    for (int i = n - 1; i > 0; i--) 
	{
        int j = distribution(g);
        swap(permuList[i], permuList[j]);
    }
	return permuList;
}

//生成逆置换列表 
vector<int> getReversePermuList(vector<int> permuList, int n)
{
	vector<int> tempList(n);
	for (int i = 0; i < n; i++)
	{
		tempList[permuList[i]] = i;
	}
	return tempList;
}

//列置换函数 
void colPermutation(vector<vector<Grid> >& grid, const vector<int>& permuList) 
{
	vector<vector<Grid> > tempGrid;
    for (int i = 0; i < grid.size(); ++i) 
	{
    	tempGrid.push_back(grid[permuList[i]]);
    }
    grid = tempGrid;
    return; 
}

void colPermutation(string &s, const vector<int>& permuList) 
{
	string tempS;
    for (int i = 0; i < s.length(); ++i) 
	{
    	tempS += s[permuList[i]];
    }
    s = tempS;
    return; 
}

//行置换函数
void rowPermutation(vector<vector<Grid> >& grid, const vector<int>& permuList) 
{
	vector<vector<Grid> > tempGrid = grid;
    for (int j = 0; j < grid[0].size(); ++j) 
	{
        for (int i = 0; i < grid.size(); ++i) 
		{
            tempGrid[i][j] = grid[i][permuList[j]];
        }
    }
    grid = tempGrid;
    return;
}

//SS的范围查询线程处理函数 
void Qthread_SS(StorageServer &SS, ComputingServer CS, ERectangle eQ, phe::Paillier pai)
{
//	thread::id this_id = this_thread::get_id();
//    cout << "Thread : " << this_id << endl;
	SS.eQ = eQ;  //拿到查询陷门 
	string tempStr;
	string xMinStr = mpz_get_str(NULL, 10, SS.eRect.eMinX);
	string xMaxStr = mpz_get_str(NULL, 10, SS.eRect.eMaxX);
	string yMinStr = mpz_get_str(NULL, 10, SS.eRect.eMinY);
	string yMaxStr = mpz_get_str(NULL, 10, SS.eRect.eMaxY);
	tempStr += (xMinStr + "|" + xMaxStr + "|" + yMinStr+ "|" + yMaxStr + "|"); 
	string hmacStr = HmacEncode_rs("md5", CS.hashKey, tempStr);  //子集范围哈希 
	
	SS.veriInfo.push_back(tempStr);
	SS.veriInfo.push_back(hmacStr);
	
	//第一阶段查询 
	mpz_t r0, r1, r2, r3, z0, z1, z2, z3;
	mpz_t E0, E1, E2, E3, D0, D1, D2, D3;
	
	mpz_inits(r0, r1, r2, r3, NULL);  //初始化大整数变量 
	mpz_inits(z0, z1, z2, z3, NULL);  //z：记录中间结果 
	mpz_inits(E0, E1, E2, E3, NULL); 
	mpz_inits(D0, D1, D2, D3, NULL);
		  
	mpz_set_si(r0, SS.genRandom());  //生成随机数 
	mpz_set_si(r1, SS.genRandom());
	mpz_set_si(r2, SS.genRandom());
	mpz_set_si(r3, SS.genRandom());
	
	pai.sub(z0, SS.eRect.eMinX, SS.eQ.eMaxX);  //减法 
	pai.sub(z1, SS.eRect.eMaxX, SS.eQ.eMinX);
	pai.sub(z2, SS.eRect.eMinY, SS.eQ.eMaxY);
	pai.sub(z3, SS.eRect.eMaxY, SS.eQ.eMinY);
	
	pai.scl_mul(E0, z0, r0);  //乘法
	pai.scl_mul(E1, z1, r1);
	pai.scl_mul(E2, z2, r2);
	pai.scl_mul(E3, z3, r3);
	
	pai.decrypt(D0, E0);  //解密 
	pai.decrypt(D1, E1);
	pai.decrypt(D2, E2);
	pai.decrypt(D3, E3);
	
	mpz_t maxValue;
	mpz_init(maxValue);
	mpz_set_str(maxValue, "10000000000", 10);  //注意： 
	
	if (mpz_cmp(D0, maxValue) > 0)  mpz_sub(D0, D0, pai.pubkey.n);
	if (mpz_cmp(D1, maxValue) > 0)  mpz_sub(D1, D1, pai.pubkey.n);
	if (mpz_cmp(D2, maxValue) > 0)  mpz_sub(D2, D2, pai.pubkey.n);
	if (mpz_cmp(D3, maxValue) > 0)  mpz_sub(D3, D3, pai.pubkey.n);
	
	mpz_t t0, t1, zero;
	mpz_inits(t0, t1, zero, NULL);
	mpz_set_ui(zero, 0);
	
	mpz_mul(t0, D0, D1);
    mpz_mul(t1, D2, D3);
    
    //判断符号 
    if (mpz_cmp(t0, zero) <= 0 && mpz_cmp(t1, zero) <= 0)   
    {
    	//继续第二阶段查询 
    	string s0, s1;
    	for (int i = 0; i < SS.gridSet.size(); i++)  //gridSet.size():列数 
    	{
    		Grid g = SS.gridSet[i][0];
    		mpz_t r00, r01, z00, z01, E00, E01, D00, D01;
    		mpz_inits(r00, r01, z00, z01, E00, E01, D00, D01, NULL); 
    		mpz_set_si(r00, SS.genRandom());  //生成随机数 
			mpz_set_si(r01, SS.genRandom());
			pai.sub(z00, g.eRect.eMinX, SS.eQ.eMaxX);  //X轴上做减法 
			pai.sub(z01, g.eRect.eMaxX, SS.eQ.eMinX);
    		pai.scl_mul(E00, z00, r00);  //乘法 
			pai.scl_mul(E01, z01, r01);
			pai.decrypt(D00, E00);  //解密 
			pai.decrypt(D01, E01);
			if (mpz_cmp(D00, maxValue) > 0)  mpz_sub(D00, D00, pai.pubkey.n);
			if (mpz_cmp(D01, maxValue) > 0)  mpz_sub(D01, D01, pai.pubkey.n);
			mpz_mul(t0, D00, D01);
    		if (mpz_cmp(t0, zero) <= 0)  s0 += "1"; 
			else  s0 += "0";
			mpz_clears(r00, r01, z00, z01, E00, E01, D00, D01, NULL);
		}
		for (int i = 0; i < SS.gridSet[0].size(); i++)  //gridSet[0].size():行数 
		{
			Grid g = SS.gridSet[0][i];
    		mpz_t r00, r01, z00, z01, E00, E01, D00, D01;
    		mpz_inits(r00, r01, z00, z01, E00, E01, D00, D01, NULL); 
    		mpz_set_si(r00, SS.genRandom());  //生成随机数 
			mpz_set_si(r01, SS.genRandom());
			pai.sub(z00, g.eRect.eMinY, SS.eQ.eMaxY);  //Y轴上做减法 
			pai.sub(z01, g.eRect.eMaxY, SS.eQ.eMinY);
    		pai.scl_mul(E00, z00, r00);  //乘法 
			pai.scl_mul(E01, z01, r01);
			pai.decrypt(D00, E00);  //解密 
			pai.decrypt(D01, E01);
			if (mpz_cmp(D00, maxValue) > 0)  mpz_sub(D00, D00, pai.pubkey.n);
			if (mpz_cmp(D01, maxValue) > 0)  mpz_sub(D01, D01, pai.pubkey.n);
			mpz_mul(t1, D00, D01);
    		if (mpz_cmp(t1, zero) <= 0)  s1 += "1"; 
			else  s1 += "0";
			mpz_clears(r00, r01, z00, z01, E00, E01, D00, D01, NULL);
		}
		string hashS0 = HmacEncode_rs("md5", CS.hashKey, s0);
		string hashS1 = HmacEncode_rs("md5", CS.hashKey, s1);
		
		for (int i = 0; i < s0.length(); i++)
		{
			for (int j = 0; j < s1.length(); j++)
			{
				if (s0[i] == '1' && s1[j] == '1')
					SS.result.push_back(SS.gridSet[i][j]);
			}
		} 
		SS.veriInfo.push_back(s0);
		SS.veriInfo.push_back(hashS0);
		SS.veriInfo.push_back(s1);
		SS.veriInfo.push_back(hashS1);
	}
    
	mpz_clears(r0, r1, r2, r3, z0, z1, z2, z3, NULL);
	mpz_clears(E0, E1, E2, E3, D0, D1, D2, D3, NULL);
	mpz_clears(t0, t1, zero, maxValue, NULL);	
}

//SS的点查询线程处理函数 
void qthread_SS(StorageServer &SS, ComputingServer CS, PaiEncPoint eq, phe::Paillier pai)
{
	SS.eq = eq;  //拿到查询陷门 
	string tempStr;
	string xMinStr = mpz_get_str(NULL, 10, SS.eRect.eMinX);
	string xMaxStr = mpz_get_str(NULL, 10, SS.eRect.eMaxX);
	string yMinStr = mpz_get_str(NULL, 10, SS.eRect.eMinY);
	string yMaxStr = mpz_get_str(NULL, 10, SS.eRect.eMaxY);
	tempStr += (xMinStr + "|" + xMaxStr + "|" + yMinStr+ "|" + yMaxStr + "|"); 
	string hmacStr = HmacEncode_rs("md5", CS.hashKey, tempStr);  //子集范围哈希 
	
	SS.veriInfo.push_back(tempStr);
	SS.veriInfo.push_back(hmacStr);
	
	//第一阶段查询 
	mpz_t r0, r1, r2, r3, z0, z1, z2, z3;
	mpz_t E0, E1, E2, E3, D0, D1, D2, D3;
	
	mpz_inits(r0, r1, r2, r3, NULL);  //初始化大整数变量 
	mpz_inits(z0, z1, z2, z3, NULL);  //z：记录中间结果 
	mpz_inits(E0, E1, E2, E3, NULL); 
	mpz_inits(D0, D1, D2, D3, NULL);
		  
	mpz_set_si(r0, SS.genRandom());  //生成随机数 
	mpz_set_si(r1, SS.genRandom());
	mpz_set_si(r2, SS.genRandom());
	mpz_set_si(r3, SS.genRandom());
	
	pai.sub(z0, SS.eRect.eMinX, SS.eq.eX);  //减法 
	pai.sub(z1, SS.eRect.eMaxX, SS.eq.eX);
	pai.sub(z2, SS.eRect.eMinY, SS.eq.eY);
	pai.sub(z3, SS.eRect.eMaxY, SS.eq.eY);
	
	pai.scl_mul(E0, z0, r0);  //乘法
	pai.scl_mul(E1, z1, r1);
	pai.scl_mul(E2, z2, r2);
	pai.scl_mul(E3, z3, r3);
	
	pai.decrypt(D0, E0);  //解密 
	pai.decrypt(D1, E1);
	pai.decrypt(D2, E2);
	pai.decrypt(D3, E3);
	
	mpz_t maxValue;
	mpz_init(maxValue);
	mpz_set_str(maxValue, "10000000000", 10);
	
	if (mpz_cmp(D0, maxValue) > 0)  mpz_sub(D0, D0, pai.pubkey.n);
	if (mpz_cmp(D1, maxValue) > 0)  mpz_sub(D1, D1, pai.pubkey.n);
	if (mpz_cmp(D2, maxValue) > 0)  mpz_sub(D2, D2, pai.pubkey.n);
	if (mpz_cmp(D3, maxValue) > 0)  mpz_sub(D3, D3, pai.pubkey.n);
	
	mpz_t t0, t1, zero;
	mpz_inits(t0, t1, zero, NULL);
	mpz_set_ui(zero, 0);
	
	mpz_mul(t0, D0, D1);
    mpz_mul(t1, D2, D3);
    
    //判断符号
    if (mpz_cmp(t0, zero) <= 0 && mpz_cmp(t1, zero) <= 0)   
    {
    	//继续第二阶段查询 
    	string s0, s1;
    	for (int i = 0; i < SS.gridSet.size(); i++)  //gridSet.size():列数 
    	{
    		Grid g = SS.gridSet[i][0];
    		mpz_t r00, r01, z00, z01, E00, E01, D00, D01;
    		mpz_inits(r00, r01, z00, z01, E00, E01, D00, D01, NULL); 
    		mpz_set_si(r00, SS.genRandom());  //生成随机数 
			mpz_set_si(r01, SS.genRandom());
			pai.sub(z00, g.eRect.eMinX, SS.eq.eX);  //X轴上做减法 
			pai.sub(z01, g.eRect.eMaxX, SS.eq.eX);
    		pai.scl_mul(E00, z00, r00);  //乘法 
			pai.scl_mul(E01, z01, r01);
			pai.decrypt(D00, E00);  //解密 
			pai.decrypt(D01, E01);
			if (mpz_cmp(D00, maxValue) > 0)  mpz_sub(D00, D00, pai.pubkey.n);
			if (mpz_cmp(D01, maxValue) > 0)  mpz_sub(D01, D01, pai.pubkey.n);
			mpz_mul(t0, D00, D01);
    		if (mpz_cmp(t0, zero) <= 0)  s0 += "1"; 
			else  s0 += "0";
			mpz_clears(r00, r01, z00, z01, E00, E01, D00, D01, NULL);
		}
		for (int i = 0; i < SS.gridSet[0].size(); i++)  //gridSet[0].size():行数 
		{
			Grid g = SS.gridSet[0][i];
    		mpz_t r00, r01, z00, z01, E00, E01, D00, D01;
    		mpz_inits(r00, r01, z00, z01, E00, E01, D00, D01, NULL); 
    		mpz_set_si(r00, SS.genRandom());  //生成随机数 
			mpz_set_si(r01, SS.genRandom());
			pai.sub(z00, g.eRect.eMinY, SS.eq.eY);  //Y轴上做减法 
			pai.sub(z01, g.eRect.eMaxY, SS.eq.eY);
    		pai.scl_mul(E00, z00, r00);  //乘法 
			pai.scl_mul(E01, z01, r01);
			pai.decrypt(D00, E00);  //解密 
			pai.decrypt(D01, E01);
			if (mpz_cmp(D00, maxValue) > 0)  mpz_sub(D00, D00, pai.pubkey.n);
			if (mpz_cmp(D01, maxValue) > 0)  mpz_sub(D01, D01, pai.pubkey.n);
			mpz_mul(t1, D00, D01);
    		if (mpz_cmp(t1, zero) <= 0)  s1 += "1"; 
			else  s1 += "0";
			mpz_clears(r00, r01, z00, z01, E00, E01, D00, D01, NULL);
		}
		string hashS0 = HmacEncode_rs("md5", CS.hashKey, s0);
		string hashS1 = HmacEncode_rs("md5", CS.hashKey, s1);
		
		for (int i = 0; i < s0.length(); i++)
		{
			for (int j = 0; j < s1.length(); j++)
			{
				if (s0[i] == '1' && s1[j] == '1')
					SS.result.push_back(SS.gridSet[i][j]);
			}
		} 
		SS.veriInfo.push_back(s0);
		SS.veriInfo.push_back(hashS0);
		SS.veriInfo.push_back(s1);
		SS.veriInfo.push_back(hashS1);
	}
    
	mpz_clears(r0, r1, r2, r3, z0, z1, z2, z3, NULL);
	mpz_clears(E0, E1, E2, E3, D0, D1, D2, D3, NULL);
	mpz_clears(t0, t1, zero, maxValue, NULL);	
}

//将字符串分段 
vector<string> segmentStr(string str, char c)
{
	vector<string> temp;
	int start = 0;
	int i = start;
	while (i < str.length()) 
	{
		if (str[i] == c)
		{
			int len = i - start;
			string subStr = str.substr(start, len);
			temp.push_back(subStr);
			start = i + 1;
			i = start;
		}
		else  i++;
	}
	return temp;
} 

//从字符串中提取出数据点 
vector<DataPoint> segmentValueStr(unsigned char *data, char c1, char c2)
{
	vector<DataPoint> dataPoints;
	istringstream iss(reinterpret_cast<char*>(data));
	string pointStr;
    while (getline(iss, pointStr, c2)) 
	{
        istringstream pointStream(pointStr);
        string xStr, yStr;
        if (getline(pointStream, xStr, c1) && getline(pointStream, yStr, c1)) 
		{
            float x = stod(xStr);
            float y = stod(yStr);
            DataPoint p;
            p.x = x;
            p.y = y;
//            if (p.x > 0 && p.y > 0)
//            	cout << p.x << ", " << p.y << endl;
            dataPoints.push_back(p);
        }
    }
	return dataPoints;
}

//读取测试文件
vector<Rectangle> readTestFile(char filename[]) 
{
    vector<Rectangle> Queries;
    ifstream inputFile(filename);
    if (!inputFile.is_open()) 
	{
        cerr << "Error opening file: " << filename << endl;
        return Queries; // 返回空的数据结构表示出错 
    }
    float x1, y1, x2, y2;
    while (inputFile >> x1 >> y1 >> x2 >> y2) 
	{
        Rectangle rect = {x1, x2, y1, y2};
        Queries.push_back(rect);
    }
    inputFile.close();
    return Queries;
}

