#include <unistd.h>
#include <getopt.h>
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

Extender * GetExtenderForHash(string sig)
{
	if(sig.length() == 40)
	{
		return new SHA1ex();
	}
	else if(sig.length() == 64)
	{
		return new SHA256ex();
	}
	else if(sig.length() == 32)
	{
		return new MD5ex();
	}
	else if(sig.length() == 128)
	{
		 return new SHA512ex();
	}
	return NULL;
}

void PrintHelp()
{
	cout << "HashPump [-h help] [-t test] [-s signature] [-d data] [-a additional] [-k keylength]" << endl;
}

int main(int argc, char ** argv)
{
	string sig;
	string data;
	int keylength;
	string datatoadd;
	Extender * sex;
	bool run_tests = false;

	while(1)
	{
		int option_index = 0;
		static struct option long_options[] = {
			{"test", no_argument, 0, 0},
			{"signature", required_argument, 0, 0},
			{"data", required_argument, 0, 0},
			{"additional", required_argument, 0, 0},
			{"keylength", required_argument, 0, 0},
			{"help", no_argument, 0, 0},
			{0, 0, 0, 0}
		};

		int c = getopt_long(argc, argv, "ts:d:a:k:h", long_options, &option_index);
		if (c == -1)
			break;

		switch(c)
		{
		case 0:
			switch(option_index)
			{
			case 0:
				run_tests = true;
				break;
			case 1:
				sig.assign(optarg);
				sex = GetExtenderForHash(sig);
				if(sex == NULL)
				{
					cout << "Unsupported signature size." << endl;
					return 0;
				}
				break;
			case 2:
				data.assign(optarg);
				break;
			case 3:
				datatoadd.assign(optarg);
				break;
			case 4:
				keylength = atoi(optarg);
				break;
			case 5:
				PrintHelp();
				return 0;
			}
			break;
			case 't':
				run_tests = true;
				break;
			case 's':
				sig.assign(optarg);
				sex = GetExtenderForHash(sig);
				if(sex == NULL)
				{
					cout << "Unsupported hash size." << endl;
					return 0;
				}
				break;
			case 'd':
				data.assign(optarg);
				break;
			case 'a':
				datatoadd.assign(optarg);
				break;
			case 'k':
				keylength = atoi(optarg);
				break;
			case 'h':
				PrintHelp();
				return 0;
		}
	}

	if(run_tests)
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

		cout << "Testing concluded" << endl;
		return 0;
	}

	if(sig.size() == 0)
	{
		cout << "Input Signature: ";
		cin >> sig;
		sex = GetExtenderForHash(sig);
		if(sex == NULL)
		{
			cout << "Unsupported hash size." << endl;
			return 0;
		}
	}

	if(data.size() == 0)
	{
		cout << "Input Data: ";
		cin >> data;
	}

	if(keylength == 0)
	{
		cout << "Input Key Length: ";
		cin >> keylength;
	}

	if(datatoadd.size() == 0)
	{
		cout << "Input Data to Add: ";
		cin >> datatoadd;
	}

	vector<unsigned char> vmessage = StringToVector((unsigned char*)data.c_str());
	vector<unsigned char> vtoadd = StringToVector((unsigned char*)datatoadd.c_str());

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
