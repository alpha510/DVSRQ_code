//2023.11.16
//���Ľ�
//Linux 
#include "DVSQ.h"
#include <thread>
#include <sstream> 
#include <queue>
#include <mutex>
#include <condition_variable> 
#include <time.h>

using namespace std; 

int main()
{
	clock_t begin;
	clock_t preEnd, trapEnd, QueryEnd, veriEnd, decEnd, refineEnd; 
	double preTime, oneTrapTime, oneQueryTime, oneVeriTime, oneDecTime, oneRefineTime;
	double trapTime, QueryTime, veriTime, decTime, refineTime;
	
	clock_t queryEnd, insertEnd, deleteEnd, updateEnd; 
	double onequeryTime, oneInsertTime, oneDeleteTime, oneUpdateTime;
	double queryTime, insertTime, deleteTime, updateTime;
	//===============================================================================//
	//--------------------------------����Ԥ����-------------------------------------//	
	begin = clock();
	
	phe::setrandom();   //���������ͨ����������������Կ�� 
    phe::Paillier pai;
    pai.keygen(KEY_LEN_BIT);
	phe::PaillierKey pubKey = pai.pubkey;  //paillier��Կ 
	phe::PaillierPrivateKey privateKey = pai.prikey;  //paillier˽Կ 
	string fixAesKey = "12345678abcdefgh12345678abcdefgh";  //AES�̶���Կ 
	string realTimeAesKey = "distributedquerydistributedquery";  //��ʼʵʱ��Կ 
	string hashKey = "012345678";  //��ϣ��Կ 
    AES aes(fixAesKey);
	
	DataOwner DO(pubKey, privateKey, fixAesKey, realTimeAesKey, hashKey);  //��ʼ��һ������ӵ����DO
	DataUser DU(pubKey, privateKey, fixAesKey, realTimeAesKey, hashKey);  //��ʼ��һ������ʹ����DU    

	char filename[20] = "HK/HK.txt";
	vector<DataPoint> dataPoints = readFile(filename);  //�������ݼ�
	cout << dataPoints.size() << endl;
	for (int i = 0; i < dataPoints.size(); i++)  //����HK���ݼ���������СΪ6λ������ 
	{
		dataPoints[i].x = dataPoints[i].x / 1000000;
		dataPoints[i].y = dataPoints[i].y / 1000000;
	}
	Rectangle rect = getDataRange(dataPoints);  //��ȡ���ݼ����ڴ���� [x:0~9][y:0~10] 
	int serverNum = SERVER_NUM;
	pair<int, int> factors = getClosestFactor(serverNum);  //��ȡX���Y�Ữ�ֶ��� 
	Server serv[SERVER_NUM];  
	partition(rect, factors, serv, dataPoints);  //Ϊÿ��server�����Ӽ� 
	vector<DataPoint> emptySet;
	dataPoints.swap(emptySet);  //�ͷ�dataPoints��ռ�ռ� 
	float theta = THETA;
	vector<VeriTable> vTable;
	vector<vector<int> > rowPermutations;
	vector<vector<int> > colPermutations;
	vector<vector<int> > rowReversePermutations;
	vector<vector<int> > colReversePermutations;
	for (int i = 0; i < SERVER_NUM; i++) 
	{
		int maxWidth = divideGrid(serv[i]);  //���Ӽ����ֳ�С����
		cout << "maxWidth = " << maxWidth << endl; 
		addFakePoints(maxWidth, serv[i], theta);  //��Ӽٵ� 
		
		dataEncryption(serv[i], pai, fixAesKey);  //���� 		
		hashSign(serv[i], hashKey);  //�����ϣ
		
		VeriTable v;
		v.serverID = i;
		v.eHash = geneVeriTable(serv[i], realTimeAesKey, v.eHashLen);  //������֤��Ϣ��
		vTable.push_back(v);
		
		vector<int> permuList1 = getPermuList(serv[i].Px);  //���û��б� 
		colPermutations.push_back(permuList1); 
		vector<int> permuList2 = getPermuList(serv[i].Py);  //���û��б� 
		rowPermutations.push_back(permuList2);
		vector<int> reversePermuList1 = getReversePermuList(permuList1, serv[i].Px);  //�����û��б� 
		colReversePermutations.push_back(reversePermuList1);
		vector<int> reversePermuList2 = getReversePermuList(permuList2, serv[i].Py);  //�����û��б�
		rowReversePermutations.push_back(reversePermuList2); 
		
		colPermutation(serv[i].gridSet, permuList1);  //���û�
		rowPermutation(serv[i].gridSet, permuList2);  //���û�  
	}
		
	TransmissionServer TS(vTable);  //��ʼ��һ����������� TS��������֤��Ϣ�� 
	ComputingServer CS(pubKey, privateKey, hashKey);  //��ʼ��һ����������� CS 
	StorageServer SS0(serv[0].eRect, serv[0].gridSet);  //�����ĸ��洢����������ʼ��
	StorageServer SS1(serv[1].eRect, serv[1].gridSet);
	StorageServer SS2(serv[2].eRect, serv[2].gridSet);
	StorageServer SS3(serv[3].eRect, serv[3].gridSet);
//	StorageServer SS4(serv[4].eRect, serv[4].gridSet);
//	StorageServer SS5(serv[5].eRect, serv[5].gridSet);
//	StorageServer SS6(serv[6].eRect, serv[6].gridSet);
//	StorageServer SS7(serv[7].eRect, serv[7].gridSet);
//	StorageServer SS8(serv[8].eRect, serv[8].gridSet);
	
	for (int i = 0; i < SERVER_NUM; i++)  //���õ�ָ�붼�ÿգ���ֹ����Ұָ�� 
	{
		for (int j = 0; j < serv[i].Px; j++)
		{
			for (int k = 0; k < serv[i].Py; k++)
			{
				serv[i].gridSet[j][k].eDataPoints = NULL;
				serv[i].gridSet[j][k].eP = NULL;
			}
		}
		vTable[i].eHash = NULL;
	}
	
	preEnd = clock();
	preTime = (double)(preEnd - begin) / CLOCKS_PER_SEC; 
	cout << "preTime = " << preTime << " s" << endl; 
	//===============================================================================//
	//--------------------------------��Χ��ѯ����-----------------------------------//
	char fname[5][50] = {"HK/HK_rect_testset1.txt", "HK/HK_rect_testset2.txt", "HK/HK_rect_testset3.txt", "HK/HK_rect_testset4.txt", "HK/HK_rect_testset5.txt"};
	char res_name[5][20] = {"HK/res_test1.txt", "HK/res_test2.txt", "HK/res_test3.txt", "HK/res_test4.txt", "HK/res_test5.txt"};

//	char fname[1][50] = {"HK/HK_rect_testset_pre.txt"};
//	char res_name[1][20] = {"HK/res_m_4.txt"};
	FILE *fp;
	for (int i = 0; i < 5; i++)
	{
		vector<Rectangle> Queries = readTestFile(fname[i]);  //����һ���µĲ����ļ� 
		for (int j = 0; j < Queries.size(); j++)
		{
			Queries[j].minX = Queries[j].minX / 1000000;
			Queries[j].maxX = Queries[j].maxX / 1000000;
			Queries[j].minY = Queries[j].minY / 1000000;
			Queries[j].maxY = Queries[j].maxY / 1000000;
		}
		if ((fp = fopen(res_name[i], "a")) == NULL)  //�򿪽��д�뼯 
		{
			cout << "Fail to open res_test" << i << ".txt" << endl;
			exit(1);
		} 
		trapTime = 0;
		QueryTime = 0;
		veriTime = 0;
		decTime = 0;
		refineTime = 0;
		
		double qt[SERVER_NUM];
		
		for (int n = 0; n < N; n++)  //�������Լ�ѭ��ִ��N�� 
		{
			int gridCnt = 0;
			for (int j = 0; j < Queries.size(); j++)  
			{
				begin = clock();
				
				bool vflag = false;  //��֤�����־
				Rectangle Q = Queries[j];
				ERectangle eQ = DU.getTrapdoor(Q, pai);  //��÷�Χ��ѯ������ 
				
				trapEnd = clock();
				oneTrapTime = (double)(trapEnd - begin) / CLOCKS_PER_SEC;
				fprintf(fp, "Trapdoor = %lf s, ", oneTrapTime);
				trapTime = trapTime + oneTrapTime; 
				
				//�ֲ�ʽ��ѯ 
//				thread SS0Qthread([&SS0,CS,eQ,pai]() {
//			        Qthread_SS(SS0,CS,eQ,pai);
//			    }); 
//			    thread SS1Qthread([&SS1,CS,eQ,pai]() {
//			        Qthread_SS(SS1,CS,eQ,pai);
//			    });
//			    thread SS2Qthread([&SS2,CS,eQ,pai]() {
//			        Qthread_SS(SS2,CS,eQ,pai);
//			    });
//			    thread SS3Qthread([&SS3,CS,eQ,pai]() {
//			        Qthread_SS(SS3,CS,eQ,pai);
//			    });
//			    thread SS4Qthread([&SS4,CS,eQ,pai]() {
//			        Qthread_SS(SS4,CS,eQ,pai);
//			    });
//			    thread SS5Qthread([&SS5,CS,eQ,pai]() {
//			        Qthread_SS(SS5,CS,eQ,pai);
//			    });
//				SS0Qthread.join();
//				SS1Qthread.join();
//				SS2Qthread.join();
//				SS3Qthread.join();
//				SS4Qthread.join();
//				SS5Qthread.join();

				trapEnd = clock();
				Qthread_SS(SS0,CS,eQ,pai);
				QueryEnd = clock();
				qt[0] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
				
				trapEnd = clock();
				Qthread_SS(SS1,CS,eQ,pai);
				QueryEnd = clock();
				qt[1] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
				
				trapEnd = clock();
				Qthread_SS(SS2,CS,eQ,pai);
				QueryEnd = clock();
				qt[2] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
				
				trapEnd = clock();
				Qthread_SS(SS3,CS,eQ,pai);
				QueryEnd = clock();
				qt[3] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
				
//				trapEnd = clock();
//				Qthread_SS(SS4,CS,eQ,pai);
//				QueryEnd = clock();
//				qt[4] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
//				
//				trapEnd = clock();
//				Qthread_SS(SS5,CS,eQ,pai);
//				QueryEnd = clock();
//				qt[5] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
//				
//				trapEnd = clock();
//				Qthread_SS(SS6,CS,eQ,pai);
//				QueryEnd = clock();
//				qt[6] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
//				
//				trapEnd = clock();
//				Qthread_SS(SS7,CS,eQ,pai);
//				QueryEnd = clock();
//				qt[7] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
//				
//				trapEnd = clock();
//				Qthread_SS(SS8,CS,eQ,pai);
//				QueryEnd = clock();
//				qt[8] = (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
				
				oneQueryTime = *max_element(qt, qt + SERVER_NUM);
				
				//TS���մ洢�������Ĳ�ѯ��� 
				trapEnd = clock();
				TS.receiveResult(SS0.result, SS0.veriInfo);
				TS.receiveResult(SS1.result, SS1.veriInfo);
				TS.receiveResult(SS2.result, SS2.veriInfo);
				TS.receiveResult(SS3.result, SS3.veriInfo);
//				TS.receiveResult(SS4.result, SS4.veriInfo);
//				TS.receiveResult(SS5.result, SS5.veriInfo);
//				TS.receiveResult(SS6.result, SS6.veriInfo);
//				TS.receiveResult(SS7.result, SS7.veriInfo);
//				TS.receiveResult(SS8.result, SS8.veriInfo);
				TS.summaryResult(0);  //TS���ܲ�ѯ�����0-->��Χ��ѯ 
				DU.FinalResult = TS.FinalResult;  //DU��TS�õ���Χ��ѯ�Ľ��
				QueryEnd = clock();
				oneQueryTime += (double)(QueryEnd - trapEnd) / CLOCKS_PER_SEC;
				fprintf(fp, "Query = %lf s, ", oneQueryTime);
				QueryTime = QueryTime + oneQueryTime; 
				
				QueryEnd = clock();
				 
				vflag = DU.verification(Q, pai, colReversePermutations, rowReversePermutations);
				
				veriEnd = clock();
				oneVeriTime = (double)(veriEnd - QueryEnd) / CLOCKS_PER_SEC;
				fprintf(fp, "Veri = %lf s, ", oneVeriTime);
				veriTime = veriTime + oneVeriTime;
				
				if (vflag == true)
				{
//					cout << "The Range Query is success!" << endl;  
					for (int ii = 0; ii < DU.FinalResult.size(); ii++)
					{
						SubResult temp = DU.FinalResult[ii];
						if(!temp.result.empty())
							gridCnt += temp.result.size();
					}
					
					DU.resultDecrypt();  //���� 
					
					decEnd = clock();
					oneDecTime = (double)(decEnd - veriEnd) / CLOCKS_PER_SEC;
					fprintf(fp, "Decrypt = %lf s, ", oneDecTime);
					decTime = decTime + oneDecTime;
					
					pair<int, int> res = DU.resultRefine(Q);  //���� 
//					cout << "resNum = " << res.first << endl;
//					cout << "nonResNum = " << res.second << endl;
					
					refineEnd = clock();
					oneRefineTime = (double)(refineEnd - decEnd) / CLOCKS_PER_SEC;
					fprintf(fp, "Refine = %lf s, ", oneRefineTime);
					refineTime = refineTime + oneRefineTime;
					
					fprintf(fp, "resNum = %d, ", res.first);
					fprintf(fp, "nonResNum = %d\n", res.second);
				}
				else
					cout << "The Range Query is failed!" << endl;
				//��ս���� 
				SS0.setEmpty();
				SS1.setEmpty();
				SS2.setEmpty();
				SS3.setEmpty();
//				SS4.setEmpty();
//				SS5.setEmpty();
//				SS6.setEmpty();
//				SS7.setEmpty();
//				SS8.setEmpty();
				TS.setEmpty();
			}
			cout << "Average_gridCnt = " << gridCnt/Queries.size() << endl;
		}
		oneTrapTime = trapTime / Queries.size() / N;
		oneQueryTime = QueryTime / Queries.size() / N;
		oneVeriTime = veriTime / Queries.size() / N;
		oneDecTime = decTime / Queries.size() / N;
		oneRefineTime = refineTime / Queries.size() / N;
		cout << "oneTrapTime = " << oneTrapTime << " s" << endl;
		cout << "oneQueryTime = " << oneQueryTime << " s" << endl;
		cout << "oneVeriTime = " << oneVeriTime << " s" << endl;
		cout << "oneDecTime = " << oneDecTime << " s" << endl;
		cout << "oneRefineTime = " << oneRefineTime << " s" << endl;
		cout << "totalTime = " << oneTrapTime+oneQueryTime+oneVeriTime+oneDecTime+oneRefineTime << " s" << endl;
		
		fprintf(fp, "AvgTrapdoor = %lf s, ", oneTrapTime);
		fprintf(fp, "AvgQuery = %lf s, ", oneQueryTime);
		fprintf(fp, "AvgVeri = %lf s, ", oneVeriTime);
		fprintf(fp, "AvgDecrypt = %lf s, ", oneDecTime);
		fprintf(fp, "AvgRefine = %lf s\n", oneRefineTime);
		fprintf(fp, "totalTime = %lf s\n", oneTrapTime+oneQueryTime+oneVeriTime+oneDecTime+oneRefineTime);
		
		if (fclose(fp) != 0) 
			cout << "res_test" << i << ".txt cannot be closed!" << endl;
	}
	//===============================================================================//*/
	/*//-------------------------------���ѯ-�������---------------------------------//
	char fname[50] = "HK/HK_point_testset.txt";
	char rname1[50] = "HK/res_insert.txt";
	FILE *fp;
	vector<DataPoint> queryPoints = readFile(fname);  //����һ���µĲ����ļ� 
	for (int i = 0; i < queryPoints.size(); i++)
	{
		queryPoints[i].x = queryPoints[i].x / 1000000;
		queryPoints[i].y = queryPoints[i].y / 1000000;
//		printf("%f %f\n", queryPoints[i].x, queryPoints[i].y);
	}
	if ((fp = fopen(rname1, "a")) == NULL)  //�򿪽��д�뼯 
	{
		cout << "Fail to open res_insert.txt" << endl;
		exit(1);
	}
	trapTime = 0;
	queryTime = 0;
	veriTime = 0;
	decTime = 0;
	insertTime = 0;
	updateTime = 0;
	
	double qt[SERVER_NUM];
	
	for (int i = 0; i < queryPoints.size(); i++)  
	{
		begin = clock();
		
		bool vflag = false;  //��֤�����־
		DataPoint q = queryPoints[i];
		PaiEncPoint eq = DO.getTrapdoor(q, pai);
		
		trapEnd = clock();
		oneTrapTime = (double)(trapEnd - begin) / CLOCKS_PER_SEC;
		fprintf(fp, "Trapdoor = %lf s, ", oneTrapTime);
		trapTime = trapTime + oneTrapTime;
		
//		thread SS0qthread([&SS0,CS,eq,pai]() {
//	        qthread_SS(SS0,CS,eq,pai);
//	    }); 
//	    thread SS1qthread([&SS1,CS,eq,pai]() {
//	        qthread_SS(SS1,CS,eq,pai);
//	    });
//	    thread SS2qthread([&SS2,CS,eq,pai]() {
//	        qthread_SS(SS2,CS,eq,pai);
//	    });
//	    thread SS3qthread([&SS3,CS,eq,pai]() {
//	        qthread_SS(SS3,CS,eq,pai);
//	    }); 
//		
//		SS0qthread.join();
//		SS1qthread.join();
//		SS2qthread.join();
//		SS3qthread.join();

		trapEnd = clock();
		qthread_SS(SS0,CS,eq,pai);
		queryEnd = clock();
		qt[0] = (double)(queryEnd - trapEnd) / CLOCKS_PER_SEC;
		
		trapEnd = clock();
		qthread_SS(SS1,CS,eq,pai);
		queryEnd = clock();
		qt[1] = (double)(queryEnd - trapEnd) / CLOCKS_PER_SEC;
		
		trapEnd = clock();
		qthread_SS(SS2,CS,eq,pai);
		queryEnd = clock();
		qt[2] = (double)(queryEnd - trapEnd) / CLOCKS_PER_SEC;
		
		trapEnd = clock();
		qthread_SS(SS3,CS,eq,pai);
		queryEnd = clock();
		qt[3] = (double)(queryEnd - trapEnd) / CLOCKS_PER_SEC;
		
		onequeryTime = *max_element(qt, qt + SERVER_NUM);
		
		trapEnd = clock();
		TS.receiveResult(SS0.result, SS0.veriInfo);
		TS.receiveResult(SS1.result, SS1.veriInfo);
		TS.receiveResult(SS2.result, SS2.veriInfo);
		TS.receiveResult(SS3.result, SS3.veriInfo);
		TS.summaryResult(1);  //1-->���ѯ 
		DO.FinalResult = TS.FinalResult;  //DO��TS�õ���Χ��ѯ�Ľ�� 
		
		queryEnd = clock();
		onequeryTime += (double)(queryEnd - trapEnd) / CLOCKS_PER_SEC;
		fprintf(fp, "PointQuery = %lf s, ", onequeryTime);
		queryTime = queryTime + onequeryTime;
		
		queryEnd = clock();
		vflag = DO.verification(q, pai, colReversePermutations, rowReversePermutations);
	
		veriEnd = clock();
		oneVeriTime = (double)(veriEnd - queryEnd) / CLOCKS_PER_SEC;
		fprintf(fp, "Veri = %lf s, ", oneVeriTime);
		veriTime = veriTime + oneVeriTime;
		
		if (vflag == true)
		{
			veriEnd = clock();
//			cout << "The Point Query is success!" << endl;   
			DO.resultDecrypt();  //����
			
			decEnd = clock();
			oneDecTime = (double)(decEnd - veriEnd) / CLOCKS_PER_SEC;
			fprintf(fp, "Decrypt = %lf s, ", oneDecTime);
			decTime = decTime + oneDecTime;
			
			decEnd = clock(); 
			DO.insertPoint(q);  //���뵥�� 			
			int sID = DO.updateGrid();  //������֤��Ϣ�� 
			Coordinate coo = DO.relocationGrid(sID, colPermutations[sID], rowPermutations[sID]);
			switch (sID) 
			{
		        case 0:
		        	SS0.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
		            break;
		            
		        case 1:
		            SS1.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
		            break;
		
		        case 2:
		            SS2.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
		            break;
		
		        case 3:
		            SS3.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
		    } 
//		    cout << "SS Update success!" << endl; 
			TS.veriTable = DO.updateVeriTable(sID);  //TS�˸�����֤��Ϣ�� 
			DU.realTimeAesKey = DO.realTimeAesKey;
			
			insertEnd = clock();
			oneInsertTime = (double)(insertEnd - decEnd) / CLOCKS_PER_SEC;
			fprintf(fp, "Insert = %lf s\n", oneInsertTime);
			insertTime = insertTime + oneInsertTime;
			
			oneUpdateTime = oneTrapTime + onequeryTime + oneVeriTime + oneDecTime + oneInsertTime;
			fprintf(fp, "Update = %lf s\n", oneUpdateTime);
			updateTime = updateTime + oneUpdateTime;
		}
		else
			cout << "The Point Query is failed!" << endl;
		//��ս���� 
		SS0.setEmpty();
		SS1.setEmpty();
		SS2.setEmpty();
		SS3.setEmpty();
		TS.setEmpty();
	}
	oneTrapTime = trapTime / queryPoints.size();
	onequeryTime = queryTime / queryPoints.size();
	oneVeriTime = veriTime / queryPoints.size();
	oneDecTime = decTime / queryPoints.size();
	oneInsertTime = insertTime / queryPoints.size();
	oneUpdateTime = updateTime / queryPoints.size();
	cout << "oneTrapTime = " << oneTrapTime << " s" << endl;
	cout << "onequeryTime = " << onequeryTime << " s" << endl;
	cout << "oneVeriTime = " << oneVeriTime << " s" << endl;
	cout << "oneDecTime = " << oneDecTime << " s" << endl;
	cout << "oneInsertTime = " << oneInsertTime << " s" << endl;
	cout << "oneUpdateTime = " << oneUpdateTime << " s" << endl;
		
	fprintf(fp, "AvgTrapdoor = %lf s, ", oneTrapTime);
	fprintf(fp, "Avgquery = %lf s, ", onequeryTime);
	fprintf(fp, "AvgVeri = %lf s, ", oneVeriTime);
	fprintf(fp, "AvgDecrypt = %lf s, ", oneDecTime);
	fprintf(fp, "AvgInsert = %lf s\n", oneInsertTime);
	fprintf(fp, "AvgUpdate = %lf s\n", oneUpdateTime);
	if (fclose(fp) != 0) 
		cout << "res_insert.txt cannot be closed!" << endl;
//	//===============================================================================//
//	//-------------------------------���ѯ-ɾ������---------------------------------//
//	char rname2[50] = "HK/delete_res_test.txt";
//	if ((fp = fopen(rname2, "a")) == NULL)  //�򿪽��д�뼯 
//	{
//		cout << "Fail to open delete_res_test.txt" << endl;
//		exit(1);
//	}
//	trapTime = 0;
//	queryTime = 0;
//	veriTime = 0;
//	decTime = 0;
//	deleteTime = 0;
//	for (int i = 0; i < queryPoints.size(); i++)  
//	{
//		begin = clock();
//		
//		bool vflag = false;  //��֤�����־
//		DataPoint q = queryPoints[i];
//		PaiEncPoint eq = DO.getTrapdoor(q, pai);
//		
//		trapEnd = clock();
//		oneTrapTime = (double)(trapEnd - begin) / CLOCKS_PER_SEC;
//		fprintf(fp, "Trapdoor = %lf s, ", oneTrapTime);
//		trapTime = trapTime + oneTrapTime;
//		
//		thread SS0qthread([&SS0,CS,eq,pai]() {
//	        qthread_SS(SS0,CS,eq,pai);
//	    }); 
//	    thread SS1qthread([&SS1,CS,eq,pai]() {
//	        qthread_SS(SS1,CS,eq,pai);
//	    });
//	    thread SS2qthread([&SS2,CS,eq,pai]() {
//	        qthread_SS(SS2,CS,eq,pai);
//	    });
//	    thread SS3qthread([&SS3,CS,eq,pai]() {
//	        qthread_SS(SS3,CS,eq,pai);
//	    }); 
//		
//		SS0qthread.join();
//		SS1qthread.join();
//		SS2qthread.join();
//		SS3qthread.join();
//		
//		TS.receiveResult(SS0.result, SS0.veriInfo);
//		TS.receiveResult(SS1.result, SS1.veriInfo);
//		TS.receiveResult(SS2.result, SS2.veriInfo);
//		TS.receiveResult(SS3.result, SS3.veriInfo);
//		TS.summaryResult(1);  //1-->���ѯ 
//		DO.FinalResult = TS.FinalResult;  //DO��TS�õ���Χ��ѯ�Ľ�� 
//		
//		queryEnd = clock();
//		onequeryTime = (double)(queryEnd - trapEnd) / CLOCKS_PER_SEC;
//		fprintf(fp, "PointQuery = %lf s, ", onequeryTime);
//		queryTime = queryTime + onequeryTime;
//		
//		vflag = DO.verification(q, pai, colReversePermutations, rowReversePermutations);
//	
//		veriEnd = clock();
//		oneVeriTime = (double)(veriEnd - queryEnd) / CLOCKS_PER_SEC;
//		fprintf(fp, "Veri = %lf s, ", oneVeriTime);
//		veriTime = veriTime + oneVeriTime;
//		
//		if (vflag == true)
//		{
//			cout << "The Point Query is success!" << endl;   
//			DO.resultDecrypt();  //����
//			
//			decEnd = clock();
//			oneDecTime = (double)(decEnd - veriEnd) / CLOCKS_PER_SEC;
//			fprintf(fp, "Decrypt = %lf s, ", oneDecTime);
//			decTime = decTime + oneDecTime;
//			 			
//			DO.deletePoint(q);  //ɾ������ 
//			int sID = DO.updateGrid();  //������֤��Ϣ�� 
//			Coordinate coo = DO.relocationGrid(sID, colPermutations[sID], rowPermutations[sID]);
//			switch (sID) 
//			{
//		        case 0:
//		        	SS0.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
//		            break;
//		            
//		        case 1:
//		            SS1.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
//		            break;
//		
//		        case 2:
//		            SS2.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
//		            break;
//		
//		        case 3:
//		            SS3.gridSet[coo.x][coo.y] = DO.FinalResult[sID].result[0];
//		    } 
//		    cout << "SS Update success!" << endl; 
//			TS.veriTable = DO.updateVeriTable(sID);  //TS�˸�����֤��Ϣ�� 
//			DU.realTimeAesKey = DO.realTimeAesKey;
//			
//			deleteEnd = clock();
//			oneDeleteTime = (double)(deleteEnd - decEnd) / CLOCKS_PER_SEC;
//			fprintf(fp, "Delete = %lf s\n", oneDeleteTime);
//			deleteTime = deleteTime + oneDeleteTime;
//		}
//		else
//			cout << "The Point Query is failed!" << endl;
//		//��ս���� 
//		SS0.setEmpty();
//		SS1.setEmpty();
//		SS2.setEmpty();
//		SS3.setEmpty();
//		TS.setEmpty();
//	}
//	oneTrapTime = trapTime / queryPoints.size();
//	onequeryTime = queryTime / queryPoints.size();
//	oneVeriTime = veriTime / queryPoints.size();
//	oneDecTime = decTime / queryPoints.size();
//	oneDeleteTime = deleteTime / queryPoints.size();
//	cout << "oneTrapTime = " << oneTrapTime << " s" << endl;
//	cout << "onequeryTime = " << onequeryTime << " s" << endl;
//	cout << "oneVeriTime = " << oneVeriTime << " s" << endl;
//	cout << "oneDecTime = " << oneDecTime << " s" << endl;
//	cout << "oneDeleteTime = " << oneDeleteTime << " s" << endl;
//	
//	fprintf(fp, "AvgTrapdoor = %lf s, ", oneTrapTime);
//	fprintf(fp, "Avgquery = %lf s, ", onequeryTime);
//	fprintf(fp, "AvgVeri = %lf s, ", oneVeriTime);
//	fprintf(fp, "AvgDecrypt = %lf s, ", oneDecTime);
//	fprintf(fp, "AvgDelete = %lf s\n", oneDeleteTime);
//	if (fclose(fp) != 0) 
//		cout << "delete_res_test.txt cannot be closed!" << endl;
//	//===============================================================================//*/
	cout << "FINISH!" << endl;	
	return 0;
}







