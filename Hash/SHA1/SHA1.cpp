// SHA1.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "SHA1.h"
#include <stdio.h>
SHA1::SHA1() {
	SHA1Init();
}
SHA1::~SHA1() {}
void SHA1::SHA1Init() {
	Length_Low = 0;
	Length_High = 0;
	Message_Block_Index = 0;
	H[0] = 0x67452301;
	H[1] = 0xEFCDAB89;
	H[2] = 0x98BADCFE;
	H[3] = 0x10325476;
	H[4] = 0xC3D2E1F0;
}

bool SHA1::Encode2Hex(const char* Data_Input, char* SHACode_Output) {
	if (NULL == Data_Input || NULL == SHACode_Output) {
		return false;
	}
	SHA1Init();
	int InputLen = strlen(Data_Input);
	int DealDataLen = 0;//保存最大处理数据的长度
	for (int pos = 0; pos <= InputLen; pos += 64) {
		if (InputLen - pos >= 64) { //数据的长度大于等于64
			DealDataLen = 64;
			memset(Message_Block, 0, sizeof(Message_Block));
			memcpy(Message_Block, Data_Input + pos, DealDataLen);
			AddDataLen(DealDataLen);//增加数据的长度
			ProcessMessageBlock();//处理数据块
			AddDataLen(0);
		}
		else //数据长度小于64，需要填充数据(补足)
		{
			DealDataLen = InputLen - pos;
			memset(Message_Block, 0, sizeof(Message_Block));
			memcpy(Message_Block, Data_Input + pos, DealDataLen);
			AddDataLen(DealDataLen);//增加数据的长度
			PadMessage();//再次打包数据
		}
	}
	//格式化写数据到整型数组,0-8,8-16,16-24,24-32
	for (int i = 0; i < 5; i++){
		sprintf(&(SHACode_Output[8*i]),"%08x",H[i]);
	}
	return true;
}
bool SHA1::Encode2Ascii(const char* Data_Input, char* SHACode_Output) {
	if (NULL == Data_Input || NULL == SHACode_Output) {
		return false;
	}
	SHA1Init();
	int InputLen = strlen(Data_Input);
	int DealDataLen = 0;//保存最大处理数据的长度
	for (int pos = 0; pos <= InputLen; pos += 64) {
		if (InputLen - pos >= 64) { //数据的长度大于64
			DealDataLen = 64;
			memset(Message_Block, 0, sizeof(Message_Block));
			memcpy(Message_Block, Data_Input + pos, DealDataLen);
			AddDataLen(DealDataLen);//增加数据的长度
			ProcessMessageBlock();//处理数据块
			AddDataLen(0);
		}
		else //数据长度小于64，需要填充数据(补足)
		{
			DealDataLen = InputLen - pos;
			memset(Message_Block, 0, sizeof(Message_Block));
			memcpy(Message_Block, Data_Input + pos, DealDataLen);
			AddDataLen(DealDataLen);//增加数据的长度
			PadMessage();//再次打包数据
		}
	}
	//得到的编码的长度是20个字节的，分5个int来存
	for (int i = 0; i < 5; i++) {
		memcpy(SHACode_Output + i * 4 + 0, (char*)&H[i] + 3, 1);
		memcpy(SHACode_Output + i * 4 + 1, (char*)&H[i] + 2, 1);
		memcpy(SHACode_Output + i * 4 + 2, (char*)&H[i] + 1, 1);
		memcpy(SHACode_Output + i * 4 + 3, (char*)&H[i] + 0, 1);
	}
	//0~3,4~7,8~15,16~19
	return true;
}

void SHA1::AddDataLen(int DataLen) {
	Message_Block_Index = DataLen;
	if ((Length_Low +=((unsigned int)DataLen << 3)) < ((unsigned int)DataLen << 3)) {
		Length_High++;
	}
	Length_High += ((unsigned int)DataLen >> 29);
}

void SHA1::ProcessMessageBlock() {
	const unsigned K[] = {   //变量定义              
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};
	int         t;                   //循环变量
	unsigned     temp;               //临时变量       
	unsigned    W[80];              //字节序列          
	unsigned    A, B, C, D, E;     //用于缓存           

	for (t = 0; t < 16; t++)//0-15
	{
		W[t] = ((unsigned)Message_Block[t * 4]) << 24;
		W[t] |= ((unsigned)Message_Block[t * 4 + 1]) << 16;
		W[t] |= ((unsigned)Message_Block[t * 4 + 2]) << 8;
		W[t] |= ((unsigned)Message_Block[t * 4 + 3]);
	}

	for (t = 16; t < 80; t++) //16-79
	{
		W[t] = CircleShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = H[0];
	B = H[1];
	C = H[2];
	D = H[3];
	E = H[4];

	//以下计算消息摘要
	for (t = 0; t < 20; t++)//0-19
	{
		temp = CircleShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = CircleShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++) //20-39
	{
		temp = CircleShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = CircleShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++)//40-59
	{
		temp = CircleShift(5, A) +
			((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = CircleShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++)//60-79
	{
		temp = CircleShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = CircleShift(30, B);
		B = A;
		A = temp;
	}

	H[0] = (H[0] + A) & 0xFFFFFFFF;
	H[1] = (H[1] + B) & 0xFFFFFFFF;
	H[2] = (H[2] + C) & 0xFFFFFFFF;
	H[3] = (H[3] + D) & 0xFFFFFFFF;
	H[4] = (H[4] + E) & 0xFFFFFFFF;

	//消息摘要的长度为160位的字符串
}

void SHA1::PadMessage() {
	if (Message_Block_Index > 55)
	{
		Message_Block[Message_Block_Index++] = 0x80;//128
		while (Message_Block_Index < 64)
		{
			Message_Block[Message_Block_Index++] = 0;
		}
		ProcessMessageBlock();
		while (Message_Block_Index < 56)
		{
			Message_Block[Message_Block_Index++] = 0;
		}
	} 
	else
	{
		Message_Block[Message_Block_Index++] = 0x80;//128
		while (Message_Block_Index < 56) {
			Message_Block[Message_Block_Index++] = 0;
		}
	}
}

unsigned SHA1::CircleShift(int bits, unsigned word) {
	return ((word << bits) & 0xFFFFFFFF) | ((word & 0xFFFFFFFF) >>(32 - bits));
}

//for test
int main(int argc, char* argv[])
{
	getchar();
	//system("pause");
    return 0;
}

