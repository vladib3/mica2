#include <rte_tcp.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sched.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include <sstream>
#include <string>
#include <list>
#include <vector>
#include <algorithm>
#include <random>
#include <time.h>
#include "mica/table/ltable.h"
#include "mica/util/hash.h"
#include "mica/util/lcore.h"

using namespace std;

// defaults
#define DEF_PKTS 10000000 // pkts num for standalone test
#define DEV_KVS_ENT 1000 // pkts for entries in mica
#define DEF_KVS 5000000 // entry number for mica

uint64_t pkts_num_per_kv = DEF_PKTS;
uint64_t kvs_num = DEF_KVS;
unsigned seed;

struct LTableConfig : public ::mica::table::BasicLosslessLTableConfig
{
  // slow
  //static constexpr bool kVerbose = true;
  // slow too
  //static constexpr bool kCollectStats = true;
};

typedef ::mica::table::LTable<LTableConfig> Table;
typedef ::mica::table::Result Result;

inline double now_double()
{
	struct timeval tv_start;
	gettimeofday(&tv_start, nullptr);
	return (double)tv_start.tv_sec * 1. + (double)tv_start.tv_usec * 0.000001;
}

// emulating ringbuffer
char *hugemem = 0;
char *hugemem_ptr = 0;
size_t hugemap_size = 1024*1024*1024;

template <typename T>
class stl_allocator
{
public:
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef T value_type;

    stl_allocator() {}
    ~stl_allocator() {}
		
    pointer allocate(size_t n)
    {
    		size_t size = n*sizeof(T);
    		if (((hugemem + hugemap_size) - hugemem_ptr) < size)
    			hugemem_ptr = hugemem;
    		auto r = hugemem_ptr;
    		hugemem_ptr += size;
        return (pointer)r;
    }

    void deallocate(pointer p, size_t n) {}
};

template <class T, class U>
inline bool operator==(const stl_allocator<T>& a, const stl_allocator<U>& b){
    return &a == &b;
}

template <class T, class U>
inline bool operator!=(const stl_allocator<T>& a, const stl_allocator<U>& b){
    return &a != &b;
}

typedef tcp_hdr *ptcp_hdr;
typedef list<ptcp_hdr, stl_allocator<ptcp_hdr>> tcp_pkt_list;
typedef tcp_pkt_list* ptcp_pkt_list;
typedef vector<ptcp_hdr> tcp_pkt_vec;
typedef tcp_pkt_vec* ptcp_pkt_vec;

// packet generation routine
inline ptcp_hdr generate_tcp_pkt(uint32_t seq)
{
	uint32_t pkt_size = 1460;
	double prob = (double)rand();
	if (prob < 0.15) // %15 probability of 9000 bytes packet
	{
		pkt_size = 9000;
	}
	ptcp_hdr pkt = (ptcp_hdr)malloc(pkt_size);
	if (!pkt)
	{
		printf("[ !  ] Can't allocate memory\n");
		exit(-1);
	}
	pkt->sent_seq = seq;
	memset(pkt, 1, pkt_size - sizeof(tcp_hdr));
	return pkt;
}

// converts text ip to long number
inline long ip_to_long(const string ip)
{
    stringstream s(ip);
    int o1, o2, o3, o4;
    char ch;
    s >> o1 >> ch >> o2 >> ch >> o3 >> ch >> o4;
    long ip_long = 0;
    ip_long = 0 | (o1 << 24) | (o2 << 16) | (o3 << 8) | o4;
    return ip_long;
}

// converts long number to text
inline string long_to_ip(const long ip){
    stringstream tmp;
    tmp << to_string((long long) ip >> 24 & 0xFF).c_str() << '.';
    tmp << to_string((long long) ip >> 16 & 0xFF).c_str() << '.';
    tmp << to_string((long long) ip >> 8 & 0xFF).c_str() << '.';
    tmp << to_string((long long) ip & 0xFF).c_str();
    return tmp.str();
}

// generates IP1:PORT2->IP2:PORT2 keys
// can produce same pairs from the begining(call reset())
class IpPairGenerator
{
	long ip_;
	long start_ip_;
	string key_; // completed pair
	uint64_t key_hash_; // hash of completed pair

public:

	IpPairGenerator(string start_ip)
	{
		start_ip_ = ip_ = ip_to_long(start_ip);
		update_key();
		update_key_hash();
	}

	// call this ALWAYS before update_key_hash()
	inline void update_key()
	{
		string ip1, ip2;
		get_pair(ip1, ip2);
		key_ = ip1 + ":1000->" + ip2 + ":80";
		
		// this part is VERY important, if key is not properly aligned,
		// then mica will insert such entry without an error, BUT will not find such entry in get request
		// 
		auto len = ::mica::util::roundup<8>(key_.length());
		auto len_diff = len - key_.length();
		for (int i = 0; i < len_diff; i++)
			key_ += " ";
	}

	inline string& get_key()
	{
		return key_;
	}

	inline void update_key_hash()
	{
		key_hash_ = ::mica::util::hash(key_.c_str(), key_.length());
	}

	inline uint64_t get_key_hash()
	{
		return key_hash_;
	}

	inline void get_pair(string &ip1, string &ip2)
	{
		ip1 = long_to_ip(ip_);
		ip2 = long_to_ip(ip_ + 1);
	}

	inline void next_pair()
	{
		ip_ += 2;
		update_key();
		update_key_hash();		
	}

	inline void reset()
	{
		ip_ = start_ip_;
		update_key();
		update_key_hash();			
	}		
};

// prebuilds tcp packets and shuffle it
void prebuild_tcp_pkts(ptcp_pkt_vec pktl)
{
	for (uint64_t i = 0; i < pkts_num_per_kv; ++i)
	{
		auto pkt = generate_tcp_pkt(i);
		pktl->push_back(pkt);
	}
	for (uint64_t i = 0; i < pkts_num_per_kv - 8; i += 8)
	{
		shuffle (pktl->begin() + i, pktl->begin() + i + 8, std::default_random_engine(seed));
	}
}

// this routine reassembles packets
template <typename T>
inline void tcp_reassemble(T pktl, ptcp_pkt_vec pktv)
{
	for (auto const &v : *pktv)
	{
		tcp_pkt_list::reverse_iterator it = pktl->rbegin();
		while (it != pktl->rend() && v->sent_seq < (*it)->sent_seq) ++it;
		pktl->insert(it.base(), v);
	}
}

// checks order of tcp packets with template (for any container type)
template<typename T>
bool tcp_check_order(T pktl)
{
	uint32_t prev = 0;
	for (auto &e : *pktl)
	{
		if (prev > e->sent_seq) return false;
	}
	return true;
}

// checks what tcp packet body isn't corrupted
bool tcp_check_packet_data_consistent(ptcp_hdr p)
{
	char *ptr = ((char*)p)+sizeof(tcp_hdr);
	for (int i = 0; i < 8; ++i)
	{
		if (ptr[i] != 1) return false;
	}
	return true;
}

// prints usage info and terminates the program
void usage_and_die(char **argv)
{
	printf("usage: %s [-e number of entries in mica2]", argv[0]);
	exit(0);
}

// comparator for sort
bool cmp_tmp(ptcp_hdr h1, ptcp_hdr h2)
{
	return h1->sent_seq < h2->sent_seq;
}

int main(int argc, char **argv)
{
	// checks for command line arguments
	int c;
	while ((c = getopt (argc, argv, "he:")) != -1)
	{
		switch (c)
		{
			case 'e':
			{
				kvs_num = stoull(optarg);
				break;
			}
			case 'h':
			{
				usage_and_die(argv);
			}
		}
	}
  // set process priority to highest
	::mica::util::lcore.pin_thread(get_nprocs() - 1);
  pid_t tid;
	tid = syscall(SYS_gettid);
	if (setpriority(PRIO_PROCESS, tid, -20))
	{
		printf("[ -  ] Can't set process priority\n");	
		exit(-1);
	}
	// create mica's classes
	auto config = ::mica::util::Config::load_file("test_tcp_reassemble.json");
	LTableConfig::Alloc alloc(config.get("alloc"));
	hugemem = hugemem_ptr = (char*)alloc.malloc_contiguous_local(hugemap_size);
  LTableConfig::Pool pool(config.get("pool"), &alloc);
  Table table(config.get("table"), &alloc, &pool);

	seed = time(0);
	srand(seed);
	// create generator for ip pairs
	IpPairGenerator ipg("1.1.1.1");
	tcp_pkt_vec pkt_vec;
	// preallocate space for packets
	pkt_vec.reserve(pkts_num_per_kv);
	printf("[ !! ] Prebuilding TCP packets\n");
	prebuild_tcp_pkts(&pkt_vec);
	double tcp_reasm_begin, tcp_reasm_tm_total;
	{
		tcp_pkt_list pkt_list;
		printf("[ !! ] Testing algorithm standalone\n");
		tcp_reasm_begin = now_double();
		// this is optimized alghoritm
		tcp_reassemble(&pkt_list, &pkt_vec);
		tcp_reasm_tm_total = now_double() - tcp_reasm_begin;
		printf("[ !! ] [ALG1] Sorting of %llu TCP packets done in (seconds): %f\n", pkts_num_per_kv, tcp_reasm_tm_total);
		if (!tcp_check_order(&pkt_list))
		{
			printf("[ -  ] TCP order error\n");
			exit(-1);
		}
		else
		{
			printf("[ +  ] TCP order is correct\n");
		}
	}
	
	
	tcp_pkt_list pkt_vec1;
	for (auto p: pkt_vec)
	{
		pkt_vec1.push_back(p);
	}
	tcp_reasm_begin = now_double();
	pkt_vec1.sort(cmp_tmp);
	tcp_reasm_tm_total = now_double() - tcp_reasm_begin;
	printf("[ !! ] [ALG2] Sorting of %llu TCP packets done in (seconds): %f\n", pkts_num_per_kv, tcp_reasm_tm_total);	
	if (!tcp_check_order(&pkt_vec1))
	{
		printf("[ -  ] TCP order error\n");
		exit(-1);
	}
	else
	{
		printf("[ +  ] TCP order is correct\n");
	}
	
	printf("[ !! ] Reducing TCP packets number to %d for each entry\n", DEV_KVS_ENT);
	pkt_vec.resize(DEV_KVS_ENT);
	printf ("[ !! ] Testing with MICA: %llu entries\n", kvs_num);
	ptcp_pkt_vec vec_addr = &pkt_vec;
	uint64_t total_inserted = 0;
	for(uint64_t i = 0; i < kvs_num; i++)
	{
		++total_inserted;
		auto key = ipg.get_key();
		auto key_hash = ipg.get_key_hash();
		if (table.set(key_hash, key.c_str(), key.length(), (char*)&vec_addr, sizeof(vec_addr), true) != Result::kSuccess)
		{
			printf("[ -  ] Can't add entry, this souldn't happen!\n");
			exit(-1);
		}
		ipg.next_pair();
	}
	
	ipg.reset();
	bool consistent_state = true;
	uint64_t total_readed = 0;
	double tcp_reasm_best = 0, tcp_reasm_worst = 0, tcp_reasm_avg = 0;
	for(uint64_t i = 0; i < kvs_num; i++)
	{
		++total_readed;
		auto key = ipg.get_key();
		auto key_hash = ipg.get_key_hash();
		ptcp_pkt_vec v;
		size_t out_value_length = sizeof(char*);
		auto tcp_reasm_mica = now_double();
		if (table.get(key_hash, key.c_str(), key.length(), (char*)&v, sizeof(char*), &out_value_length, false) == Result::kSuccess)
		{
			tcp_pkt_list lst;
			tcp_reassemble(&lst, v);
			auto tcp_reasm_mica_tm = now_double() - tcp_reasm_mica;
			if (tcp_reasm_best == 0)
				tcp_reasm_best = tcp_reasm_mica_tm;
			else if (tcp_reasm_mica_tm < tcp_reasm_best)
				tcp_reasm_best = tcp_reasm_mica_tm;
			else if (tcp_reasm_mica_tm > tcp_reasm_worst)
				tcp_reasm_worst = tcp_reasm_mica_tm;
			tcp_reasm_avg += tcp_reasm_mica_tm;
			if (!tcp_check_order(&lst))
			{
				printf("[ -  ] TCP order error\n");
				exit(-1);
			}
			
			for (auto p : lst)
			{
				if (!tcp_check_packet_data_consistent(p))
					consistent_state = false;
			}			
		}
		else
		{
			printf("[ -  ] %s entry not found, this souldn't happen!\n", key.c_str());
			exit(-1);
		}
		ipg.next_pair();
	}

	printf("[ +  ] Total entries added: %llu\n", total_inserted);
	printf("[ +  ] Total entries found: %llu\n", total_readed);
	if (consistent_state)
		printf("[ +  ] TCP packets are not corrupted\n");
	else
		printf("[ -  ] TCP packets are corrupted\n");
	printf("[ +  ] TCP sorting of 1000 TCP packets with MICA avg: %f\n", tcp_reasm_avg/total_readed);

	exit(0);
	//table.print_stats();

	return 0;
	
}