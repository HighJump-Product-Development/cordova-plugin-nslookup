/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1997,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

 /*
    Code based on https://github.com/hsccorp/cordova-dnsjava-nslookup/blob/master/src/ios/CDVNslookup.m
 */

#import <Cordova/CDV.h>
#include <resolv.h>

void dump_dns(const u_char *payload, size_t paylen, const char *endline) ;
static void dump_dns_rr(ns_msg *msg, ns_rr *rr, ns_sect sect);
static void dump_dns_sect(ns_msg *msg, ns_sect sect, const char *endline);

@interface Nslookup : CDVPlugin {

}

- (void)getNsLookupInfo:(CDVInvokedUrlCommand *)command;


@end

@implementation Nslookup
NSMutableDictionary *completeResult;
NSMutableDictionary *responseObj;
NSMutableArray *tempResultArr;
NSMutableArray *completeResultArr;

#define MY_GET16(s, cp) do { \
register const u_char *t_cp = (const u_char *)(cp); \
(s) = ((u_int16_t)t_cp[0] << 8) \
| ((u_int16_t)t_cp[1]) \
; \
(cp) += NS_INT16SZ; \
} while (0)

#define MY_GET32(l, cp) do { \
register const u_char *t_cp = (const u_char *)(cp); \
(l) = ((u_int32_t)t_cp[0] << 24) \
| ((u_int32_t)t_cp[1] << 16) \
| ((u_int32_t)t_cp[2] << 8) \
| ((u_int32_t)t_cp[3]) \
; \
(cp) += NS_INT32SZ; \
} while (0)


- (void) getNsLookupInfo:(CDVInvokedUrlCommand*)command
{
    [self.commandDelegate runInBackground:^{
        completeResultArr = [[NSMutableArray alloc] init];

        NSUInteger arraySize = [command.arguments count];
        u_char answer[1024] = "";
        struct __res_state res;
        res_ninit(&res);
        
        NSUInteger i;
        for(i = 0; i < arraySize; i++) {
            NSString *query = command.arguments[i][@"query"];
            NSString *type =  command.arguments[i][@"type"];
            
            const char *currQuery = [query UTF8String];
            const char *currType = [type UTF8String];
            int tempType;
            if (strcmp(currType, "TXT") == 0)
            {
                tempType = ns_t_txt;
                int rv = res_nquery(&res, currQuery, ns_c_in, tempType, answer, sizeof(answer));
                dump_dns(answer, rv, "\n");
                if(rv > -1) {
                    responseObj[@"status"] = @"success";
                }
                else {
                    responseObj[@"status"] = @"error";
                    
                }
                completeResult[@"query"] = query;
                completeResult[@"type"] = type;
                completeResult[@"result"] = tempResultArr;
                [completeResultArr addObject:completeResult];
            } else {
                // Record types not implemented
                completeResult[@"query"] = query;
                completeResult[@"type"] = type;
            }


        }

        CDVPluginResult* pluginResult = nil;
        
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:completeResultArr];
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

void dump_dns(const u_char *payload, size_t paylen, const char *endline) {
    completeResult = [[NSMutableDictionary alloc] init];
    responseObj = [[NSMutableDictionary alloc] init];
    tempResultArr = [[NSMutableArray alloc] init];
    ns_msg msg;

    if (ns_initparse(payload, (int) paylen, &msg) < 0) {
        return;
    }
    dump_dns_sect(&msg, ns_s_an, endline);
}

static void dump_dns_sect(ns_msg *msg, ns_sect sect, const char *endline) {
    int rrnum, rrmax;
    ns_rr rr;
    rrmax = ns_msg_count(*msg, sect);
    if (rrmax == 0) {
        return;
    }
    for (rrnum = 0; rrnum < rrmax; rrnum++) {
        if (ns_parserr(msg, sect, rrnum, &rr)) {
            return;
        }
        dump_dns_rr(msg, &rr, sect);
    }
}


static void dump_dns_rr(ns_msg *msg, ns_rr *rr, ns_sect sect) {
    char buf[NS_MAXDNAME];
    u_int class, type;
    const u_char *rd;
    class = ns_rr_class(*rr);
    type = ns_rr_type(*rr);
    rd = ns_rr_rdata(*rr);
    snprintf(buf, ns_rr_rdlen(*rr), "%s", rd+1);
    int tokenLen = rd[0];
    while(buf[tokenLen]) {
        int currTokenLen = tokenLen;
        tokenLen = tokenLen + buf[tokenLen] + 1;
        buf[currTokenLen] = ',';
    }
    NSString *strings = [NSString stringWithFormat:@"[%s]" , buf];
    NSDictionary *result = @{@"strings":strings};
    [tempResultArr addObject:result ];
}

@end
