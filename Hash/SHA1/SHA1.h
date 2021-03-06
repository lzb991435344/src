#ifndef _SHA1_H_
#define _SHA1_H_
#pragma once

#include <stdio.h>
#include <string.h>

/**SHA1
*   安全哈希算法（Secure Hash Algorithm）主要适用于数字签名标准 
*（Digital Signature Standard DSS）里面定义的数字签名算法
*（Digital Signature Algorithm DSA）。对于长度小于2^64位的消息，
*SHA1会产生一个160位的消息摘要。当接收到消息的时候，这个消息摘要
*可以用来验证数据的完整性。
*
*/
/**
*	usage    :    char SHABuffer[41];
*                    SHA1 SHA;
*                    SHA.SHA_GO("gfc",SHABuffer);
*                    执行完成之后SHABuffer中即存储了由"a string"计算得到的SHA值
*	算法描述：
*		1.填充形成整512 bits(64字节), (N+1)*512;
*		 N*512 + 448位                         64位
*		真实数据 + 填充(一个1和无数个0)                 保存真实数据的长度
*		—————————————————————— ----------------------
*		2.四个32位被称为连接变量的整数参数：
*		A=，B=，C=，D=,E=
*		3.开始算法的四轮循环运算。
*		循环的次数(N+1)是信息中512位信息分组的数目。
*		for(N+1, 每次取512 bits(64字节)来进行处理：)
*		{
*		512bits 分成16个分组(每个分组4字节。int data[16])
*		用16个分组中的每一个分组和A，B，C，D,E通过4个函数进行运算，
*		得到新的A，B，C，D,E
*		}
*		4.最后，将A，B，C，D,E拼接起来就是SHA值
*		将拼接后的值用字符串的方式表示出来，就是最终的结果。
*		(比如 0x234233F, 用串 “234233F”表示出来，生成的串的空间将是值的空间的2倍。)
*/
class SHA1
{
public:
	SHA1();
	virtual ~SHA1();
	bool Encode2Hex(const char* Data_Input, char* SHACode_Output);
	bool Encode2Ascii(const char* Data_Input, char* SHACode_Output);
protected:
private:
	unsigned int H[0x05];//20个字节
	unsigned int Length_High;//high 高位的数据
	unsigned int Length_Low;//low 低位的数据
	unsigned char  Message_Block[0x40]; //64
	unsigned int Message_Block_Index;//消息块的索引
private:
	/**
	@commmon 初始化
	@param 
	@return void
	*/
	void SHA1Init();

	/**
	@commmon 增加数据的长度
	@param int nDataLen:要增加的长度
	@return void
	*/
	void AddDataLen(int DataLen);

	/**
	@commmon 打包数据
	@param int nDataLen:要增加的长度
	@return void
	*/
	void PadMessage();

	/**
	@commmon 处理消息块
	@param 
	@return void
	*/
	void ProcessMessageBlock();

	/**
	@commmon 循环移位
	@param int bits:移位的位数
	       unsigned word 移位的数据
	@return void
	*/
	inline unsigned CircleShift(int bits, unsigned word);
};
#endif
