#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

#include <vector>
#include <map>
#include <set>
#include <queue>
#include <stack>
#include <iterator>
#include <cstring>

using namespace std;

struct val
{
	/* data */
	string ip;
	string ep;
};

struct criterion
{
	/* data */
	string ip;
	string ep;
	string target;
};

ofstream ofile;
map<criterion, val> asMap;
inline bool operator < (const struct criterion &k1, const struct criterion &k2) {  
    return k1.ip < k2.ip || (k1.ip==k2.ip && k1.ep<k2.ep) || (k1.ip==k2.ip && k1.ep==k2.ep&&k1.target<k2.target);  
}

queue<criterion> cqueue;
stack<criterion> result;

// split string line into tokens
vector<string> getTokens(string s)
{
	vector<string> tokens;
	/* Method 1 */
	// istringstream iss(line);
	// vector<string> tokens;
	// copy(istream_iterator<string>(iss), istream_iterator<string>(), back_inserter(tokens));

	/* Method 2 */
	char *str=const_cast<char *>(s.c_str());  
	char *tok = strtok(str, ", ");
	while(tok != NULL)
	{
		tokens.push_back(tok);
		tok = strtok(NULL, ", ");
	}
	return tokens;
}

// split string line into tokens and wrap tokens up
void wrappCriterion(string line)
{
	vector<string> tok = getTokens(line);
	criterion c = {tok[1], tok[2], tok[3]};
	val v = {tok[4], tok[5]};
	asMap[c] = v;
}

criterion wrapVal2C(val v)
{
	criterion c = {v.ip, v.ep, ""};
	return c;
}

// output slice sequence
void output()
{
	ofile.open("slice.txt");
	criterion c;
	while(!result.empty())
	{
		c = result.top();
		ofile << c.ip << " " << c.ep << endl;
		cout << c.ip << " " << c.ep << endl;
		result.pop();
	}
	ofile.close();
}

/* 
	Given a criterion and get a val[ip, ep], not find unique slice seq. 
	Iteratively searching the val from keys in criterion map. 
	If match, put all potential criterions into the queue, if not, current val is the last slice
*/
void findTarByVal(val v)
{
	int flg = 0;
	for(map<criterion, val>::iterator it = asMap.begin(); it != asMap.end(); it++) 
	{
		criterion c = it->first;
		if(c.ip==v.ip && c.ep==v.ep)
		{
			cqueue.push(c);
			flg++;
		}
	}
	if(!flg) result.push(wrapVal2C(v));
}

// find the next slice by given a criterion
void findValByCriterion(criterion c)
{
	findTarByVal(asMap[c]);
}

void parser()
{
	criterion c;
	while(!cqueue.empty()) {
		c = cqueue.front();
		// put into result
		result.push(c);
		cqueue.pop();
		findValByCriterion(c);
	}
	// when queue is empty, find all the criterions
	output();
}

void usage()
{
	printf("\n"
		"Insufficient input arguments\n"
		"Usage: filename followed by slice criterion !\n"
		"i.e."
		"	./parser filename 0x400590 0x1 0x601044\n");
	exit(1);
}

void init(char *f)
{
	ifstream file(f);
	string line;
	while(getline(file, line))
	{
		wrappCriterion(line);
	}
}

int main (int argc, char *argv[]) 
{
	// 1 - file | 2:4 - slice criterion [0x400590, 0x1, 0x601044]
	if(argc < 5) usage();
	init(argv[1]);
	char *p1 = strtok(argv[2], ", ");
	p1 = strtok(NULL, ", ");
	char *p2 = strtok(argv[3], ", ");
	p2 = strtok(NULL, ", ");
	char *p3 = strtok(argv[4], ", ");
	p3 = strtok(NULL, ", ");
	criterion fc = {argv[2], argv[3], argv[4]};
	cqueue.push(fc);

	// start to parse
	parser();
	return 0;
}