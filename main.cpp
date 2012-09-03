
#include <openssl/sha.h>
#include "SHA1.h"
#include "MD5ex.h"
#include "SHA256.h"
#include "SHA512ex.h"

using namespace std;

vector<unsigned char> StringToVector(unsigned char * str)
{
	vector<unsigned char> ret;
	for(unsigned int x = 0; x < strlen((char*)str); x++)
	{
		ret.push_back(str[x]);
	}
	return ret;
}

void DigestToRaw(string hash, unsigned char * raw)
{
	transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
	string alpha("0123456789abcdef");
	for(unsigned int x = 0; x < (hash.length() / 2); x++)
	{
		raw[x] = (unsigned char)((alpha.find(hash.at((x * 2))) << 4));
		raw[x] |= (unsigned char)(alpha.find(hash.at((x * 2) + 1)));
	}
}

vector<unsigned char> * GenerateRandomData()
{
	vector<unsigned char> * ret = new vector<unsigned char>();
	int length = rand() % 128;
	for(int x = 0; x < length; x++)
	{
		ret->push_back((rand() % (126 - 32)) + 32);
	}
	return ret;
}

void TestExtender(Extender * sex)
{
	//First generate a signature, with randomly generated data
	vector<unsigned char> * vkey = GenerateRandomData();
	vector<unsigned char> * vmessage = GenerateRandomData();
	vector<unsigned char> * additionalData = GenerateRandomData();
	unsigned char * firstSig;
	unsigned char * secondSig;
	sex->GenerateSignature(*vkey, *vmessage, &firstSig);
	if(sex->ValidateSignature(*vkey, *vmessage, firstSig))
	{
		vector<unsigned char> * newData = sex->GenerateStretchedData(*vmessage, vkey->size(), firstSig, *additionalData, &secondSig);
		if(sex->ValidateSignature(*vkey, *newData, secondSig))
		{
			cout << "Test passed." << endl;
			delete vkey;
			delete vmessage;
			delete additionalData;
			delete newData;
			return;
		}
		else
		{
			cout << "Generated data failed to be verified as correctly signed." << endl;
			delete vkey;
			delete vmessage;
			delete additionalData;
			delete newData;
			return;
		}
	}
	else
	{
		cout << "Initial signature check failed." << endl;
		delete vkey;
		delete vmessage;
		delete additionalData;
		return;
	}
}

int main(int argc, char ** argv)
{
	if(argc < 2)
	{
		cout << "Input Signature: ";
		string sig;
		cin >> sig;
		cout << sig.length() << endl;
		cout << "Input Data: ";
		string data;
		cin >> data;
		int keylength;
		cout << "Input Key Length: ";
		cin >> keylength;
		string datatoadd;
		cout << "Input Data to Add: ";
		cin >> datatoadd;

		vector<unsigned char> vmessage = StringToVector((unsigned char*)data.c_str());
		vector<unsigned char> vtoadd = StringToVector((unsigned char*)datatoadd.c_str());

		Extender * sex;

		if(sig.length() == 40)
		{
			sex = new SHA1ex();
		}
		else if(sig.length() == 64)
		{
			sex = new SHA256ex();
		}
		else if(sig.length() == 32)
		{
			sex = new MD5ex();
		}
		else if(sig.length() == 128)
		{
			sex = new SHA512ex();
		}
		else
		{
			cout << "Hash size does not match a known algorithm." << endl;
			return 1;
		}

		unsigned char firstSig[20];
		DigestToRaw(sig, firstSig);
		unsigned char * secondSig;
		vector<unsigned char> * secondMessage = sex->GenerateStretchedData(vmessage, keylength, firstSig, vtoadd, &secondSig);
		for(int x = 0; x < 20; x++)
		{
			printf("%02x", secondSig[x]);
		}
		cout << endl;
		for(unsigned int x = 0; x < secondMessage->size(); x++)
		{
			unsigned char c = secondMessage->at(x);
			if(c >= 32 && c <= 126)
			{
				cout << c;
			}
			else
			{
				printf("\\x%02x", c);
			}
		}
		delete secondMessage;
		cout << endl;
		return 0;
	}
	else
	{
		//Just a simple way to force tests
		cout << "Testing SHA1" << endl;
		TestExtender(new SHA1ex());

		cout << "Testing SHA256" << endl;
		TestExtender(new SHA256ex());

		cout << "Testing SHA512" << endl;
		TestExtender(new SHA512ex());

		cout << "Testing MD5" << endl;
		TestExtender(new MD5ex());
	}
}
