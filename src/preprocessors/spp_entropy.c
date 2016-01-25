
/*
** Copyright (C) <2015>  <Han Zhang>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* Snort High Entropy Detection Preprocessor Plugin
 *   by Han Zhang <zhanghan0116@gmail.com>
 *   Version 0.1.0
 */

/* spp_entropy
 *
 * Purpose: Detects high entropy data including encrypted data, compressed data, vedio, etc. The high entropy will not be delivered to the following detection modules relying DPI techniques because such high entropy data can not be understood by DPI. By doing this, the performance can be improved largely.
 *
 * Arguments: read from configuration file
 *
 *
 */

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "generators.h"
#include "log.h"
#include "detect.h"
#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "parser.h"
#include "snort_debug.h"
#include "mstring.h"
#include "util.h"
#include "event_queue.h"
/* In case we need to drop this packet */
#include "active.h"
#include "snort.h"
#include "profiler.h"
#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
//#include "sf_snort_packet.h"


#define CONF_SEPARATORS         " \t\n\r"
#define HASH_MOD 10000
#define ENT_SIZE 70000
#define MAX_SIZE 2048
//#define PktsLimit 15
#define HASH_MOD 10000
#define REFRESH_INTERVAL 10
#define PKTSPERFLOW 10240
#define EntropyThresholdFile "/PathTo/EntropyThreshold_PY_64K"

extern FILE * LOG_FILE_DESCRIPTOR;
struct timeval start_time;
struct timeval end_time;
int time_set = 0;


typedef struct _FlowRecord
{
	int pkt_entropy[PKTSPERFLOW];
	int packet_count;
	char src_ip[17];
	char dst_ip[17];
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t proto;
	int have_payload;
	long first_sec;
	long first_usec;
	long last_sec;
	long last_usec;
	int labeled;
	struct _FlowRecord * prev;
	struct _FlowRecord * next;
} FlowRecord;

struct EntropyThreshold
{
        int BeginOffset;
        int EndOffset;
        float entropy_low;
        float entropy_up;
};

typedef struct _HashNode
{
    FlowRecord * hash_flow_header;
} HashNode;

typedef struct _EntropyConfig
{
	int he_percent;
	int seq_he_pkts;
	int first_pkts;

} EntropyConfig;

int SEQ_HIGH_ENTROPY = 0;	//read from configuration file
int HEPercent = 0;			//read from configuration file
int PktsLimit = 0;			//read from configuration file
int TotalEncryptFlows = 0;
int TotalNonEncryptFlows = 0;
int TIMEOUT = 30;
int first_packet = 0;
int packet_count = 0;
uint32_t last_sec = 0;
uint32_t current_sec = 0;
uint32_t current_pkt_sec = 0;
FlowRecord * flow_header = NULL;
FlowRecord * flow_last = NULL;
struct EntropyThreshold EntThresh[ENT_SIZE];
HashNode hash_table[HASH_MOD];

#ifdef PERF_PROFILING
PreprocStats entropyPerfStats;
#endif

static tSfPolicyUserContextId entropy_config = NULL;

/* list of function prototypes for this preprocessor */
static void EntropyInit(struct _SnortConfig *, char *);
static void HEDetection(Packet *, void *);

/* list of private functions */
static void PrecalcPrefix(void);
static void ProcessArgs(EntropyConfig *, char *args);
static void EntropyFreeConfig(tSfPolicyUserContextId entropy);
static void EntropyCleanExit(int, void *);
static int GetEntropyThreshold(char *);
static int AboveEntropy(char * , int);
static void UpdateFlows(char * , char * , uint16_t , uint16_t , uint16_t , uint32_t , long , long , char * , uint16_t, uint16_t, Packet *);
static void RefreshFlows();
static int DecideHighEntropyFlow(FlowRecord *);


#ifdef SNORT_RELOAD
static void EntropyReload(struct _SnortConfig *, char *, void **);
static void * EntropyReloadSwap(struct _SnortConfig *, void *);
static void EntropyReloadSwapFree(void *);
#endif

char * _inet_ntoa(struct in_addr in)
{
	static char b[18];
	register char *p;

	p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
	(void)snprintf(b, sizeof(b),
	    "%d.%d.%d.%d", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);
}


static void UpdateFlows(char * src_ip, char * dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t proto, uint32_t seq_number, long sec, long usec, char * payload, uint16_t payload_size, uint16_t hash_value, Packet *p)
{
	//printf("UpdateFlows\n");
	FlowRecord * ite_record = hash_table[hash_value].hash_flow_header;
	//the first node in the index
	if(ite_record == NULL)
	{
		FlowRecord * new_record = (FlowRecord *)malloc(sizeof(FlowRecord));
		new_record->pkt_entropy[0] = AboveEntropy(payload, payload_size);
		if(payload_size > 16)
		{
			new_record->have_payload = 1;
		}
		else
		{
			new_record->have_payload = 0;
		}
		new_record->packet_count = 1;
		new_record->labeled = -1;
		strcpy(new_record->src_ip, src_ip);
		strcpy(new_record->dst_ip, dst_ip);
		new_record->proto = proto;
		new_record->first_sec = sec;
		new_record->first_usec = usec;
		new_record->src_port = src_port;
		new_record->dst_port = dst_port;
		new_record->last_sec = sec;
		new_record->last_usec = usec;
		new_record->prev = NULL;
		new_record->next = NULL;
		hash_table[hash_value].hash_flow_header = new_record;
		return;
	}

	while(1)
	{
		//find the right record
		if( ( (proto == ite_record->proto) && (strcmp(ite_record->src_ip, src_ip) == 0)&&(strcmp(ite_record->dst_ip, dst_ip) == 0)&&(ite_record->src_port == src_port)&&(ite_record->dst_port == dst_port) ) ||
		( (strcmp(ite_record->src_ip, dst_ip) == 0)&&(strcmp(ite_record->dst_ip, src_ip) == 0)&&(ite_record->src_port == dst_port)&&(ite_record->dst_port == src_port) && (proto == ite_record->proto) ) )
		{
			if(ite_record->labeled == -1)
			{
				if(ite_record->packet_count < PKTSPERFLOW)
				{
					ite_record->pkt_entropy[ite_record->packet_count] = AboveEntropy(payload, payload_size);
				}
				if(ite_record->packet_count == PktsLimit)
				{
					//printf("Decide\n");
					DecideHighEntropyFlow(ite_record);	
				}
				if(payload_size > 0)
				{
					ite_record->have_payload = 1;
				}
			}
			else if(ite_record->labeled == 1)
			{
				//printf("Drop packet\n");
				DisableAllDetect(p);
				Active_DropSession(p);
			}
			ite_record->packet_count++;
			ite_record->last_sec = sec;
			ite_record->last_usec = usec;
			return;
		}
		if(ite_record->next != NULL)
		{
			ite_record = ite_record->next;
		}
		else
		{
			break;
		}
	}
	FlowRecord * new_record = (FlowRecord *)malloc(sizeof(FlowRecord));
	new_record->pkt_entropy[0] = AboveEntropy(payload, payload_size);
	new_record->packet_count = 1;
	if(payload_size > 0)
	{
		new_record->have_payload = 1;
	}
	else
	{
		new_record->have_payload = 0;
	}
	new_record->labeled = -1;
	strcpy(new_record->src_ip, src_ip);
	strcpy(new_record->dst_ip, dst_ip);
	new_record->src_port = src_port;
	new_record->dst_port = dst_port;
	new_record->proto = proto;
	new_record->first_sec = sec;
	new_record->first_usec = usec;
	new_record->last_sec = sec;
	new_record->last_usec = usec;
	new_record->prev = ite_record;
	new_record->next = NULL;
	ite_record->next = new_record;
}

static void RefreshFlows()
{
	int hf_total = 0;
	int i = 0;
	int temp_counter = 0;
	for(i=0; i<HASH_MOD; i++)
	{
		FlowRecord * ite_record = hash_table[i].hash_flow_header;
		FlowRecord * temp_record;
		if(ite_record == NULL)
		{
			continue;
		}
		while(ite_record)
		{
			if( (current_sec - ite_record->last_sec > TIMEOUT) || (TIMEOUT == -1) )
			{
				hf_total = DecideHighEntropyFlow(ite_record);
				//delete the timeouted record
				if(ite_record->prev == NULL)	//the first record in the index
				{
					hash_table[i].hash_flow_header = ite_record->next;
					if(ite_record->next != NULL)
					{
						ite_record->next->prev = NULL;	
					}
					temp_record = ite_record->next;
					free(ite_record);
					ite_record = temp_record;
				}
				else
				{
					ite_record->prev->next = ite_record->next;
					if(ite_record->next != NULL)
					{
						ite_record->next->prev = ite_record->prev;
					}
					temp_record = ite_record->next;
					free(ite_record);
					ite_record = temp_record;
				}
			}
			else
			{
				ite_record = ite_record->next;
			}
		}
	}
}

static int DecideHighEntropyFlow(FlowRecord * flow_record)
{
	int i = 0;
	int j = 0;
	int SEQSys = 0;
	int SkipPacket = 0;
	int repeat_packet = 0;
	int TotalPktNumber = 0;
	int TotalEncrypt = 0;
	int TotalNonEncrypt = 0;
	int SequentEncrypt = 0;
	int EncryptPktAfterSeq = 0;
	int NonEncryptPktAfterSeq = 0;
	int TotalZeroPayload = 0;
	int ZeroPayloadAfterSeq = 0;
	//printf("DecideHighEntropyFlow\n");
	if(flow_record->have_payload != 1)
	{
		return 0;
	}

	//the flow record has been labeled
	if(flow_record->labeled != -1)
	{
		return 0;
	}
	for(i=0; i < flow_record->packet_count; i++)
	{
		if(i >= PktsLimit)
		{
			break;
		}
		repeat_packet = 0;
		TotalPktNumber++;
		/*check whether packet has high entropy*/
		if(flow_record->pkt_entropy[i] == 1)
		{
			TotalEncrypt++;
			SequentEncrypt++;

			/*the first encrypted packet*/
			if(SequentEncrypt == 1)
			{
				EncryptPktAfterSeq++;
				ZeroPayloadAfterSeq = 0;
			}
			else if(SequentEncrypt < SEQ_HIGH_ENTROPY)
			{
				EncryptPktAfterSeq++;
			}
			else if(SequentEncrypt == SEQ_HIGH_ENTROPY)
			{
				/*set the flow as have N sequential high entropy packets*/
				SEQSys = 1;
				SkipPacket = TotalPktNumber - SEQ_HIGH_ENTROPY - ZeroPayloadAfterSeq;
				EncryptPktAfterSeq = SequentEncrypt;
			}
			else if(SequentEncrypt > SEQ_HIGH_ENTROPY)
			{
				EncryptPktAfterSeq++;
			}
		}
		/*the packet has low entropy*/
		else if( flow_record->pkt_entropy[i] == -1 )
		{
			TotalNonEncrypt++;
			/*the flow doesn't have N sequential high entropy packets*/
			if(SequentEncrypt < SEQ_HIGH_ENTROPY)
			{
				EncryptPktAfterSeq = 0;
				NonEncryptPktAfterSeq = 0;
				ZeroPayloadAfterSeq = 0;
				SequentEncrypt = 0;
			}
			/*the flow has N sequential high entropy packets*/
			else if(SequentEncrypt >= SEQ_HIGH_ENTROPY)
			{
				NonEncryptPktAfterSeq++;
			}
		}
		else if(flow_record->pkt_entropy[i] == 0)
		{
			TotalZeroPayload++;
			ZeroPayloadAfterSeq++;
		}
	}

	if((SEQSys == 1) && ( EncryptPktAfterSeq * 100 > ( EncryptPktAfterSeq + NonEncryptPktAfterSeq) * HEPercent))
	{
		flow_record->labeled = 1;
		OptTreeNode * otn = OtnLookup(snort_conf->otn_map, GENERATOR_SPP_ENTROPY, HE_TRAFFIC_DETECT);
		char log_timestamp[TIMEBUF_SIZE];
		struct timeval log_timeval;
		char proto[16];
		log_timeval.tv_sec = flow_record->first_sec;
		log_timeval.tv_usec = flow_record->first_usec;
		ts_print(&log_timeval, log_timestamp);
		if(flow_record->proto == 6)
		{
			strcpy(proto, "TCP");
		}
		else if(flow_record->proto == 17)
		{
			strcpy(proto, "UDP");
		}
		fprintf(LOG_FILE_DESCRIPTOR, "\n[**] [%d:%d:%d] %s [**]\n[Classification: %s] [Priority: %d]\n %s %s %s:%d <-> %s:%d\n", otn->sigInfo.generator, otn->sigInfo.id, otn->sigInfo.rev, otn->sigInfo.message, otn->sigInfo.classType->name, otn->sigInfo.priority, log_timestamp, proto, flow_record->src_ip, flow_record->src_port, flow_record->dst_ip, flow_record->dst_port);
		TotalEncryptFlows++;
		return 1;
	}
	else
	{
		flow_record->labeled = 0;
		TotalNonEncryptFlows++;
		return -1;
	}
	return 0;
}

static int GetEntropyThreshold(char * file_in)
{
	FILE * fp_read = NULL;
	int BeginOffset;
	int EndOffset;
	float entropy_low;
	float entropy_up;
	int count = 0;
	char temp[MAX_SIZE];
	char * p = NULL;

	printf("Read Entropy Threshold File\n");
	if((fp_read=fopen(file_in, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Read Entropy Threshold File Failed\n");
		exit(1);
	}
	while(!feof(fp_read))        //read the dat file and analysis
	{
		memset(temp, '\0', sizeof(temp));
		fgets(temp, sizeof(temp), fp_read);
		if(feof(fp_read))
		{
			break;
		}
		if(temp[0]=='#')
		{
			continue;
		}
		else
		{
			p = strtok(temp, " ");
			if(p)
			{
				BeginOffset = atoi(p);
			}
			p = strtok(NULL, " ");
			/*if(p)
			{
				EndOffset = atoi(p);
			}*/
			p = strtok(NULL, " ");
			if(p)
			{
				entropy_low = atof(p);
			}
			p = strtok(NULL, " ");
			if(p)
			{
				entropy_up = atof(p);
			}
		}
		EntThresh[count].BeginOffset = BeginOffset;
		//EntThresh[count].EndOffset = EndOffset;
		EntThresh[count].entropy_low = entropy_low;
		EntThresh[count].entropy_up = entropy_up;
		count++;
		if(count >= ENT_SIZE)
		{
			break;
		}
	}
}

static int AboveEntropy(char * payload, int payload_size)
{
	/*return -1 if low entropy, 0 for no payload, 1 for high entropy*/
	int count[256];
	int i = 0;
	double entropy = 0;
	if(payload_size == 0)
	{
		return 0;
	}
	for(i=0; i<256; i++)
	{
		count[i] = 0;
	}
	for(i=0; i < payload_size; i++)
	{
		count[payload[i]+128]++;
	}

	for(i=0; i<256; i++)
	{
		if(count[i] > 0)
		{
			entropy = entropy - (double)(count[i])/(double)(payload_size)*(double)((log2(count[i]) - log2(payload_size)));
		}
	}
	if(entropy > EntThresh[payload_size-1].entropy_low)
	{
		return 1;
	}
	else
	{
		return -1;
	}
}

void SetupEntropy(void)
{
    /* link the preprocessor keyword to the init function in
       the preproc list */
#ifndef SNORT_RELOAD
    RegisterPreprocessor("entropy", EntropyInit);
#else
    RegisterPreprocessor("entropy", EntropyInit, EntropyReload, NULL, EntropyReloadSwap, EntropyReloadSwapFree);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                "Preprocessor: High Entropy Flows Detection\n"););
}

static void EntropyInit(struct _SnortConfig *sc, char *args)
{
    int policy_id = (int)getParserPolicy(sc);
    EntropyConfig *pPolicyConfig = NULL;

    if (entropy_config == NULL)
    {
        //create a context
        entropy_config = sfPolicyConfigCreate();

        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: High Entropy Initialized\n"););

        //AddFuncToPreprocCleanExitList(EntropyCleanExit, NULL, PRIORITY_LAST, PP_BO);
        AddFuncToPreprocCleanExitList(EntropyCleanExit, NULL, PRIORITY_LAST, PP_ENTROPY);

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("backorifice", &entropyPerfStats, 0, &totalPerfStats);
#endif
    }

    sfPolicyUserPolicySet (entropy_config, policy_id);
    pPolicyConfig = (EntropyConfig *)sfPolicyUserDataGetCurrent(entropy_config);
    if (pPolicyConfig)
    {
        ParseError("Entropy preprocessor can only be configured once.\n");
    }

    pPolicyConfig = (EntropyConfig *)SnortAlloc(sizeof(EntropyConfig));
    if (!pPolicyConfig)
    {
        ParseError("Entropy preprocessor: memory allocate failed.\n");
    }

    sfPolicyUserDataSetCurrent(entropy_config, pPolicyConfig);

    /* Process argument list */
    ProcessArgs(pPolicyConfig, args);

    LogMessage("LINE: %d\n", __LINE__);

    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(sc, HEDetection, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

    int i = 0;
    GetEntropyThreshold(EntropyThresholdFile);
    for(i=0; i<HASH_MOD; i++)
    {
        hash_table[i].hash_flow_header = NULL;
    }
}

static void ProcessArgs(EntropyConfig *entropy, char *args)
{
    char *arg;

    if ((args == NULL) || (entropy == NULL))
        return;

    arg = strtok(args, CONF_SEPARATORS);

    while ( arg != NULL )
    {
	LogMessage("arg: %s\n", arg);
        if ( !strcasecmp("he_percent", arg) )
        {
			//entropy->he_percent = (uint16_t)ProcessOptionList();
			arg = strtok(NULL, CONF_SEPARATORS);
			entropy->he_percent = atoi(arg);
			HEPercent = entropy->he_percent;
		}
        else if ( !strcasecmp("seq_he_pkts", arg) )
        {
            //bo->seq_he_pkts = (uint16_t)ProcessOptionList();
			arg = strtok(NULL, CONF_SEPARATORS);
			entropy->seq_he_pkts = atoi(arg);
			SEQ_HIGH_ENTROPY = entropy->seq_he_pkts;
		}
		else if( !strcasecmp("first_pkts", arg))
		{
            //bo->seq_he_pkts = (uint16_t)ProcessOptionList();
			arg = strtok(NULL, CONF_SEPARATORS);
            entropy->first_pkts = atoi(arg);
	    	PktsLimit = entropy->first_pkts;
		}
        else
        {
            FatalError("%s(%d) => Unknown entropy option %s.\n",
                        file_name, file_line, arg);
        }
		arg = strtok(NULL, CONF_SEPARATORS);

    }
    LogMessage("HE_Percent: %d, Seq_he_pkts: %d, First_pkts: %d\n", HEPercent, SEQ_HIGH_ENTROPY, PktsLimit);
    //printf("HE_Percent: %d, Seq_he_pkts: %d, First_pkts: %d\n", HEPercent, SEQ_HIGH_ENTROPY, PktsLimit);
}

static void HEDetection(Packet *p, void *context)
{
    char *pkt_data;
    char *end;
    char plaintext;
    int i;
    uint16_t hash_value = 0;
    int entropy_direction = 0;
    EntropyConfig *entropy = NULL;

    sfPolicyUserPolicySet (entropy_config, getRuntimePolicy());
    entropy = (EntropyConfig *)sfPolicyUserDataGetCurrent(entropy_config);

    /* Not configured in this policy */
    if (entropy == NULL)
        return;

    if(time_set == 0)
    {
		memset(&start_time, 0, sizeof(start_time));
		gettimeofday(&start_time, NULL);
		time_set = 1;
    }

    if( (p->dsize > 16) && (p->ip_dsize > 0) && (p->dsize < 1500 ) && ( (p->iph->ip_proto == 6) || (p->iph->ip_proto == 17) ) )
    {
	    pkt_data = (char*)p->data;

	    char src_ip[17];
	    char dst_ip[17];
	    struct in_addr src_cp;
	    struct in_addr dst_cp;
	    //_inet_ntoa(src_cp);
	    src_cp.s_addr = p->iph->ip_src.s_addr;
	    dst_cp.s_addr = p->iph->ip_dst.s_addr;
	    strcpy(src_ip, _inet_ntoa(src_cp));
	    strcpy(dst_ip, _inet_ntoa(dst_cp));
    	//LogMessage("packet: %ld %ld %s %d %s %d %d %d\n", p->pkth->ts.tv_sec, p->pkth->ts.tv_usec, src_ip, p->sp, dst_ip, p->dp, p->dsize, p->ip_dsize);
		current_pkt_sec = p->pkth->ts.tv_sec;
		hash_value = (src_cp.s_addr + dst_cp.s_addr + p->sp + p->dp)%HASH_MOD;
		if(p->iph->ip_proto == 6)
		{
			UpdateFlows(src_ip, dst_ip, p->sp, p->dp, p->iph->ip_proto, p->tcph->th_seq, p->pkth->ts.tv_sec, p->pkth->ts.tv_usec, pkt_data, p->dsize, hash_value, p);
		}
		else if(p->iph->ip_proto == 17)
		{
			UpdateFlows(src_ip, dst_ip, p->sp, p->dp, p->iph->ip_proto, 0, p->pkth->ts.tv_sec, p->pkth->ts.tv_usec, pkt_data, p->dsize, hash_value, p);
		}
		current_sec = p->pkth->ts.tv_sec;
		if(first_packet == 0)
		{
			last_sec = p->pkth->ts.tv_sec;
			first_packet = 1;
		}
		if(p->pkth->ts.tv_sec - last_sec > REFRESH_INTERVAL)
		{
			RefreshFlows();
			last_sec = p->pkth->ts.tv_sec;
		}
    }
    return;
}

static int EntropyFreeConfigPolicy(tSfPolicyUserContextId entropy, tSfPolicyId policyId, void* pData)
{
    EntropyConfig *pPolicyConfig = (EntropyConfig *)pData;
    sfPolicyUserDataClear (entropy, policyId);
    free(pPolicyConfig);
    return 0;
}

static void EntropyFreeConfig(tSfPolicyUserContextId entropy)
{
    if (entropy == NULL)
        return;

    sfPolicyUserDataFreeIterate (entropy, EntropyFreeConfigPolicy);
    sfPolicyConfigDelete(entropy);
}

static void EntropyCleanExit(int signal, void *unused)
{
    TIMEOUT = -1;
    RefreshFlows();
    memset(&end_time, 0, sizeof(end_time));
    gettimeofday(&end_time, NULL);
    uint64_t milliseconds = ((end_time.tv_sec - start_time.tv_sec) * 1000) +
        (((1000000 + end_time.tv_usec - start_time.tv_usec) / 1000) - 1000);
    printf("time elapsed %.3fs", (float)milliseconds/(float)1000);
    EntropyFreeConfig(entropy_config);
    entropy_config = NULL;
}

#ifdef SNORT_RELOAD
static void EntropyReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId entropy_swap_config = (tSfPolicyUserContextId)*new_config;
    int policy_id = (int)getParserPolicy(sc);
    EntropyConfig *pPolicyConfig = NULL;
    if (!entropy_swap_config)
    {
        entropy_swap_config = sfPolicyConfigCreate();
        *new_config = (void *)entropy_swap_config;
    }
    sfPolicyUserPolicySet (entropy_swap_config, policy_id);
    pPolicyConfig = (EntropyConfig *)sfPolicyUserDataGetCurrent(entropy_swap_config);
    if (pPolicyConfig)
    {
        ParseError("Entropy preprocessor can only be configured once.\n");
    }
    pPolicyConfig = (EntropyConfig *)SnortAlloc(sizeof(EntropyConfig));
    if (!pPolicyConfig)
    {
        ParseError("Entropy preprocessor: memory allocate failed.\n");
    }
    sfPolicyUserDataSetCurrent(entropy_swap_config, pPolicyConfig);
    ProcessArgs(pPolicyConfig, args);
    AddFuncToPreprocList(sc, HEDetection, PRIORITY_TRANSPORT, PP_ENTROPY, PROTO_BIT__TCP | PROTO_BIT__UDP);
}

static void * EntropyReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId entropy_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = entropy_config;
    if (entropy_swap_config == NULL)
        return NULL;
    entropy_config = entropy_swap_config;
    entropy_swap_config = NULL;
    return (void *)old_config;
}

static void EntropyReloadSwapFree(void *data)
{
    if (data == NULL)
        return;
    EntropyFreeConfig((tSfPolicyUserContextId )data);
}
#endif

