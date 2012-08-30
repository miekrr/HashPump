#include "MD5ex.h"

MD5ex::MD5ex()
{

}

int MD5ex::GenerateSignature(vector<unsigned char> key, vector<unsigned char> message, unsigned char ** signature)
{
	*signature = new unsigned char[16];
	MD5_CTX original;
	MD5_Init(&original);
	int totalLen = key.size() + message.size();
	unsigned char * tohash = new unsigned char[totalLen];
	for(unsigned int x = 0; x < key.size(); x++)
	{
		tohash[x] = key[x];
	}
	for(unsigned int x = 0; x < message.size(); x++)
	{
		tohash[x + key.size()] = message[x];
	}
	MD5_Update(&original, tohash, totalLen);
	delete [] tohash;
	MD5_Final(*signature, &original);
	return 1;
}

bool MD5ex::ValidateSignature(vector<unsigned char> key, vector<unsigned char> message, unsigned char * signature)
{
	MD5_CTX original;
	MD5_Init(&original);
	int totalLen = key.size() + message.size();
	unsigned char * tohash = new unsigned char[totalLen];
	for(unsigned int x = 0; x < key.size(); x++)
	{
		tohash[x] = key[x];
	}
	for(unsigned int x = 0; x < message.size(); x++)
	{
		tohash[x + key.size()] = message[x];
	}
	MD5_Update(&original, tohash, totalLen);
	delete [] tohash;
	unsigned char hash[16];
	MD5_Final(hash, &original);
	if(memcmp(hash, signature, 16) == 0)
	{
		return true;
	}
	return false;
}

vector<unsigned char> MD5ex::GenerateStretchedData(vector<unsigned char> originalMessage, int keylength, unsigned char * hash, vector<unsigned char> added, unsigned char ** newSig)
{
	int tailLength = originalMessage.size() + keylength;
	tailLength *= 8;
	originalMessage.push_back(0x80);
	while((originalMessage.size() + keylength + 4) % 64 != 0)
	{
		originalMessage.push_back(0x00);
	}
	originalMessage.push_back((tailLength >> 24) & 0xFF);
	originalMessage.push_back((tailLength >> 16) & 0xFF);
	originalMessage.push_back((tailLength >> 8) & 0xFF);
	originalMessage.push_back((tailLength) & 0xFF);
	MD5_CTX stretch;
	MD5_Init(&stretch);
	stretch.Nl = (originalMessage.size() + keylength) * 8;
	stretch.A = hash[3] | (hash[2] << 8) | (hash[1] << 16) | (hash[0] << 24);
	stretch.B = hash[7] | (hash[6] << 8) | (hash[5] << 16) | (hash[4] << 24);
	stretch.C = hash[11] | (hash[10] << 8) | (hash[9] << 16) | (hash[8] << 24);
	stretch.D = hash[15] | (hash[14] << 8) | (hash[13] << 16) | (hash[12] << 24);
	char * toadd = new char[added.size()];
	for(unsigned int x = 0; x < added.size(); x++)
	{
		toadd[x] = added[x];
	}
	MD5_Update(&stretch, toadd, added.size());
	*newSig = new unsigned char[16];
	MD5_Final(*newSig, &stretch);
	delete [] toadd;
	for(unsigned int x = 0; x < added.size(); x++)
	{
		originalMessage.push_back(added.at(x));
	}
	return originalMessage;
}
