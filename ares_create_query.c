
/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "openssl/md5.h"




#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include "ares_nameser.h"

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"


/* Header format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * AA, TC, RA, and RCODE are only set in responses.  Brief description
 * of the remaining fields:
 *      ID      Identifier to match responses with queries
 *      QR      Query (0) or response (1)
 *      Opcode  For our purposes, always O_QUERY
 *      RD      Recursion desired
 *      Z       Reserved (zero)
 *      QDCOUNT Number of queries
 *      ANCOUNT Number of answers
 *      NSCOUNT Number of name server records
 *      ARCOUNT Number of additional records
 *
 * Question format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The query name is encoded as a series of labels, each represented
 * as a one-byte length (maximum 63) followed by the text of the
 * label.  The list is terminated by a label of length zero (which can
 * be thought of as the root domain).
 */


//void bytes2md5(const char *data, int len, char *md5buf) {
//  // Based on https://www.openssl.org/docs/manmaster/man3/EVP_DigestUpdate.html
//  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
//  const EVP_MD *md = EVP_md5();
//  unsigned char md_value[EVP_MAX_MD_SIZE];
//  unsigned int md_len, i;
//  EVP_DigestInit_ex(mdctx, md, NULL);
//  EVP_DigestUpdate(mdctx, data, len);
//  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
//
//  printf("md_value: %s\n", md_value);
//
//  //printf("md_value len: %d\n", strlen(md_value))
//
//  printf("md_len: %d\n", md_len);
//
//  EVP_MD_CTX_free(mdctx);
//  for (i = 0; i < md_len; i++) {
//    snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
//  }
//}


//-------------------------
// URL INFO
//-------------------------
struct xx_url_t {
    char	str[1024];	/* URL strings */
};

/*------------------------------------------------------------------------------*/
/*
 * @brief   get hostname from URL (URL文字列からhost名を取得)
 * @param	[i/o]	buf		work-buffer
 * @param	[in]	in		URL-strings
 * @retval	*p			host-strings
 * @retval	*"\0"			error
 */
/*------------------------------------------------------------------------------*/
char * func_cut_host( struct xx_url_t *buf, const char * in )
{
  static	char	*blank = "\0";
  int	err;
  char	*p;

  // check argument
  if ( buf != NULL && in != NULL ){

    // check buffer overflow
    if ( sizeof(buf->str) > strlen(in) ) {

      // get 2nd part.
      //     ex:"http://www.a.b.c/cgi/jobs.cgi?h=99&z=3" -> www.a.b.c
      //     ex:"file:///tmp/test.txt" -> tmp
      err = sscanf( in, "%*[^/]%*[/]%[^/]", buf->str);
      if ( 1 == err ) {
        p = buf->str;
      } else {
        // sscanf error
        p = blank;
      }
    }else {
      // buffer overflow
      p = blank;
    }
  }else {
    // invalid argument
    p = blank;
  }
  return p;
}




int ares_create_query(const char *name, int dnsclass, int type,
                      unsigned short id, int rd, unsigned char **bufp,
                      int *buflenp, int max_udp_size)
{
  size_t len;
  unsigned char *q;
  const char *p;
  size_t buflen;
  unsigned char *buf;

//  struct xx_url_t	buf_url;
//
//  const char* url_ = urls_c_str;
//
//  char *token, *str, *tofree;
//  tofree = str = strdup(urls_c_str); // we own hostnames_c_str's memory now
//
//  char* name = func_cut_host( &buf_url, urls_c_str );

  const char* url_ = name;

  const char* name2 = name;



//  printf("name len: %d\n", strlen(name));
//  printf("name: %s\n", name);

  /* Set our results early, in case we bail out early with an error. */
  *buflenp = 0;
  *bufp = NULL;

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN. */
  if (ares__is_onion_domain(name))
    return ARES_ENOTFOUND;

  /* Allocate a memory area for the maximum size this packet might need. +2
   * is for the length byte and zero termination if no dots or ecscaping is
   * used.
   */
//  len = strlen(name) + 2 + HFIXEDSZ + QFIXEDSZ +
//    (max_udp_size ? EDNSFIXEDSZ : 0) + strlen(name) + 2 + 2 + 4 + 2 + 5 + 1;


  len = strlen(name) + 2 + HFIXEDSZ + QFIXEDSZ +
        (max_udp_size ? EDNSFIXEDSZ : 0) + strlen(name) + 2 + 2 + 4 + 2 + 5 + 1 + 100;



  int len2 = len;

  buf = ares_malloc(len);
  if (!buf)
    return ARES_ENOMEM;

  /* Set up the header. */
  q = buf;
  memset(q, 0, HFIXEDSZ);
  DNS_HEADER_SET_QID(q, id);
  DNS_HEADER_SET_OPCODE(q, O_QUERY);
  if (rd) {
    DNS_HEADER_SET_RD(q, 1);
  }
  else {
    DNS_HEADER_SET_RD(q, 0);
  }
  DNS_HEADER_SET_QDCOUNT(q, 1);

  if (max_udp_size) {
//      DNS_HEADER_SET_ARCOUNT(q, 1);
      DNS_HEADER_SET_ARCOUNT(q, 2); // added qos, so the number of additional should be 2
  }


  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(name, ".") == 0)
    name++;

  /* Start writing out the name after the header. */
  q += HFIXEDSZ;

  unsigned char* p_name_begin = NULL;

  while (*name)
    {
      if (*name == '.') {
        ares_free (buf);
        return ARES_EBADNAME;
      }

      /* Count the number of bytes in this label. */
      len = 0;
      for (p = name; *p && *p != '.'; p++)
        {
          if (*p == '\\' && *(p + 1) != 0)
            p++;
          len++;
        }
      if (len > MAXLABEL) {
        ares_free (buf);
        return ARES_EBADNAME;
      }

      /* Encode the length and copy the data. */
      *q++ = (unsigned char)len;
      p_name_begin = q;
      for (p = name; *p && *p != '.'; p++)
        {
          if (*p == '\\' && *(p + 1) != 0)
            p++;
          *q++ = *p;
        }

      /* Go to the next label and repeat, unless we hit the end. */
      if (!*p)
        break;
      name = p + 1;
    }

  unsigned char* p_name_end = q;

  /* Add the zero-length label at the end. */
  *q++ = 0;



  /* Finish off the question with the type and class. */
  DNS_QUESTION_SET_TYPE(q, type);
  DNS_QUESTION_SET_CLASS(q, dnsclass);

  q += QFIXEDSZ; // QFIXEDSZ == 4

  unsigned char* t1 = q;

  // set opt
  if (max_udp_size)
  {
      memset(q, 0, EDNSFIXEDSZ);
      q++;
      DNS_RR_SET_TYPE(q, T_OPT);
      DNS_RR_SET_CLASS(q, max_udp_size);
      q += (EDNSFIXEDSZ-1);
  }

//  char* t2 = p;

//  printf("opt len: %ld\n", q - t1);


  int ret, i;


//  unsigned char md[MD5_DIGEST_LENGTH];
//  unsigned char buf_md[MD5_DIGEST_LENGTH * 2 + 1];


  char* buf_md = "0A137B375CC3881A70E186CE2172C8D1";

//  MD5_CTX c;
//
//  const void *data = url_;
//  //1. 初始化
//  ret = MD5_Init(&c);
//  if (1 != ret)
//  {
//    printf("MD5_Init failed...\n");
//    return 1;
//  }
//
////  2. 添加数据
//  ret = MD5_Update(&c, (const void *)data, strlen((char *)data));
//  if (1 != ret)
//  {
//    printf("MD5_Update failed...\n");
//    return 1;
//  }
//
//  //3. 计算结果
//  ret = MD5_Final(md, &c);
//  if (1 != ret)
//  {
//    printf("MD5_Final failed...\n");
//    return 1;
//  }
//
//  //4. 输出结果
////  cout << "md: " << md << endl;
//  printf("md: %s\n", md);
//  memset(buf_md, 0, MD5_DIGEST_LENGTH * 2 + 1);
//  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
//  {
//    sprintf((char*)&buf_md[i * 2], "%02X", md[i]);
//  }
//
//  printf("buf_md: %s\n", buf_md);
//  printf("buf_md len: %d\n", strlen(buf_md));





////  char* name3 = "www.google.com";
  char* name3 = "\003www\006google\003com";

//  printf("name3 len: %d\n", strlen(name3));

  strcpy(q, name3);

  q += strlen(name3) + 1;


  //type
  DNS_RR_SET_TYPE(q, T_QOS);
//  q += 2;
  //class
  DNS_RR_SET_CLASS(q, C_QOS_Query);
//  q += 2;
  // ttl
  DNS_RR_SET_TTL(q, 0);
//  q += 4;
  //RDLength
//  DNS_RR_SET_LEN(q, 6); // this is one only for test data "12345\0"
  DNS_RR_SET_LEN(q, strlen(buf_md));// this is is copying string, 32bytes
//  DNS_RR_SET_LEN(q, MD5_DIGEST_LENGTH); // this is copying bytes stream, 16bytes
//  DNS_RR_SET_LEN(q, strlen(buf_md)); // this is copying bytes stream, 16bytes
//  DNS_RR_SET_LEN(q, MD5_DIGEST_LENGTH * 2); // this is copying bytes stream, 16bytes
//  q += 2;

  q += (2 + 2 + 4 + 2);

  //RData
//  char* hash_url = "12345";
//  char* hash_url = buf_md; this is is copying string, 32bytes
//  char* hash_url = md;// this is copying bytes stream, 16bytes
//  strcpy(q, hash_url);
//  q += strlen(hash_url);
//  *q++ = 0; // '\0'

//    strcpy(q, md);
//    strcpy(q, buf_md);
//
  memcpy(q, buf_md, strlen(buf_md));
//  memcpy(q, buf_md, MD5_DIGEST_LENGTH * 2);
//  q += (MD5_DIGEST_LENGTH * 2);
//  q += MD5_DIGEST_LENGTH;
  q += strlen(buf_md);
//    q += (2*MD5_DIGEST_LENGTH);


//    *q++ = 0; // '\0'



  buflen = (q - buf);

  /* Reject names that are longer than the maximum of 255 bytes that's
   * specified in RFC 1035 ("To simplify implementations, the total length of
   * a domain name (i.e., label octets and label length octets) is restricted
   * to 255 octets or less."). */
  if (buflen > (size_t)(MAXCDNAME + HFIXEDSZ + QFIXEDSZ +
                (max_udp_size ? EDNSFIXEDSZ : 0))) {
    ares_free (buf);
    return ARES_EBADNAME;
  }

  /* we know this fits in an int at this point */
  *buflenp = (int) buflen;
  *bufp = buf;

  return ARES_SUCCESS;
}


int ares_create_query_hash(const char *name, const char* hash_url, int dnsclass, int type,
                      unsigned short id, int rd, unsigned char **bufp,
                      int *buflenp, int max_udp_size)
{
  size_t len;
  unsigned char *q;
  const char *p;
  size_t buflen;
  unsigned char *buf;

//  struct xx_url_t	buf_url;
//
//  const char* url_ = urls_c_str;
//
//  char *token, *str, *tofree;
//  tofree = str = strdup(urls_c_str); // we own hostnames_c_str's memory now
//
//  char* name = func_cut_host( &buf_url, urls_c_str );

  const char* url_ = name;

  const char* name2 = name;



//  printf("name len: %d\n", strlen(name));
//  printf("name: %s\n", name);

  /* Set our results early, in case we bail out early with an error. */
  *buflenp = 0;
  *bufp = NULL;

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN. */
  if (ares__is_onion_domain(name))
    return ARES_ENOTFOUND;

  /* Allocate a memory area for the maximum size this packet might need. +2
   * is for the length byte and zero termination if no dots or ecscaping is
   * used.
   */
//  len = strlen(name) + 2 + HFIXEDSZ + QFIXEDSZ +
//    (max_udp_size ? EDNSFIXEDSZ : 0) + strlen(name) + 2 + 2 + 4 + 2 + 5 + 1;


  len = strlen(name) + 2 + HFIXEDSZ + QFIXEDSZ +
        (max_udp_size ? EDNSFIXEDSZ : 0) + strlen(name) + 2 + 2 + 4 + 2 + 5 + 1 + 100;



  int len2 = len;

  buf = ares_malloc(len);
  if (!buf)
    return ARES_ENOMEM;

  /* Set up the header. */
  q = buf;
  memset(q, 0, HFIXEDSZ);
  DNS_HEADER_SET_QID(q, id);
  DNS_HEADER_SET_OPCODE(q, O_QUERY);
  if (rd) {
    DNS_HEADER_SET_RD(q, 1);
  }
  else {
    DNS_HEADER_SET_RD(q, 0);
  }
  DNS_HEADER_SET_QDCOUNT(q, 1);

  if (max_udp_size) {
//      DNS_HEADER_SET_ARCOUNT(q, 1);
    DNS_HEADER_SET_ARCOUNT(q, 2); // added qos, so the number of additional should be 2
  }


  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(name, ".") == 0)
    name++;

  /* Start writing out the name after the header. */
  q += HFIXEDSZ;

  unsigned char* p_name_begin = NULL;

  while (*name)
  {
    if (*name == '.') {
      ares_free (buf);
      return ARES_EBADNAME;
    }

    /* Count the number of bytes in this label. */
    len = 0;
    for (p = name; *p && *p != '.'; p++)
    {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      len++;
    }
    if (len > MAXLABEL) {
      ares_free (buf);
      return ARES_EBADNAME;
    }

    /* Encode the length and copy the data. */
    *q++ = (unsigned char)len;
    p_name_begin = q;
    for (p = name; *p && *p != '.'; p++)
    {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      *q++ = *p;
    }

    /* Go to the next label and repeat, unless we hit the end. */
    if (!*p)
      break;
    name = p + 1;
  }

  unsigned char* p_name_end = q;

  /* Add the zero-length label at the end. */
  *q++ = 0;



  /* Finish off the question with the type and class. */
  DNS_QUESTION_SET_TYPE(q, type);
  DNS_QUESTION_SET_CLASS(q, dnsclass);

  q += QFIXEDSZ; // QFIXEDSZ == 4

  unsigned char* t1 = q;

  // set opt
  if (max_udp_size)
  {
    memset(q, 0, EDNSFIXEDSZ);
    q++;
    DNS_RR_SET_TYPE(q, T_OPT);
    DNS_RR_SET_CLASS(q, max_udp_size);
    q += (EDNSFIXEDSZ-1);
  }

//  char* t2 = p;

//  printf("opt len: %ld\n", q - t1);


  int ret, i;


//  unsigned char md[MD5_DIGEST_LENGTH];
//  unsigned char buf_md[MD5_DIGEST_LENGTH * 2 + 1];


  const char* buf_md = hash_url;

//  MD5_CTX c;
//
//  const void *data = url_;
//  //1. 初始化
//  ret = MD5_Init(&c);
//  if (1 != ret)
//  {
//    printf("MD5_Init failed...\n");
//    return 1;
//  }
//
////  2. 添加数据
//  ret = MD5_Update(&c, (const void *)data, strlen((char *)data));
//  if (1 != ret)
//  {
//    printf("MD5_Update failed...\n");
//    return 1;
//  }
//
//  //3. 计算结果
//  ret = MD5_Final(md, &c);
//  if (1 != ret)
//  {
//    printf("MD5_Final failed...\n");
//    return 1;
//  }
//
//  //4. 输出结果
////  cout << "md: " << md << endl;
////  printf("md: %s\n", md);
//  memset(buf_md, 0, MD5_DIGEST_LENGTH * 2 + 1);
//  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
//  {
//    sprintf((char*)&buf_md[i * 2], "%02X", md[i]);
//  }

//  printf("buf_md: %s\n", buf_md);
//  printf("buf_md len: %d\n", strlen(buf_md));





////  char* name3 = "www.google.com";
  char* name3 = "\003www\006google\003com";

//  printf("name3 len: %d\n", strlen(name3));

  strcpy(q, name3);

  q += strlen(name3) + 1;


  //type
  DNS_RR_SET_TYPE(q, T_QOS);
//  q += 2;
  //class
  DNS_RR_SET_CLASS(q, C_QOS_Query);
//  q += 2;
  // ttl
  DNS_RR_SET_TTL(q, 0);
//  q += 4;
  //RDLength
//  DNS_RR_SET_LEN(q, 6); // this is one only for test data "12345\0"
  DNS_RR_SET_LEN(q, strlen(buf_md));// this is is copying string, 32bytes
//  DNS_RR_SET_LEN(q, MD5_DIGEST_LENGTH); // this is copying bytes stream, 16bytes
//  DNS_RR_SET_LEN(q, strlen(buf_md)); // this is copying bytes stream, 16bytes
//  DNS_RR_SET_LEN(q, MD5_DIGEST_LENGTH * 2); // this is copying bytes stream, 16bytes
//  q += 2;

  q += (2 + 2 + 4 + 2);

  //RData
//  char* hash_url = "12345";
//  char* hash_url = buf_md; this is is copying string, 32bytes
//  char* hash_url = md;// this is copying bytes stream, 16bytes
//  strcpy(q, hash_url);
//  q += strlen(hash_url);
//  *q++ = 0; // '\0'

//    strcpy(q, md);
//    strcpy(q, buf_md);
//
  memcpy(q, buf_md, strlen(buf_md));
//  memcpy(q, buf_md, MD5_DIGEST_LENGTH * 2);
//  q += (MD5_DIGEST_LENGTH * 2);
//  q += MD5_DIGEST_LENGTH;
  q += strlen(buf_md);
//    q += (2*MD5_DIGEST_LENGTH);


//    *q++ = 0; // '\0'



  buflen = (q - buf);

  /* Reject names that are longer than the maximum of 255 bytes that's
   * specified in RFC 1035 ("To simplify implementations, the total length of
   * a domain name (i.e., label octets and label length octets) is restricted
   * to 255 octets or less."). */
  if (buflen > (size_t)(MAXCDNAME + HFIXEDSZ + QFIXEDSZ +
                        (max_udp_size ? EDNSFIXEDSZ : 0))) {
    ares_free (buf);
    return ARES_EBADNAME;
  }

  /* we know this fits in an int at this point */
  *buflenp = (int) buflen;
  *bufp = buf;

  return ARES_SUCCESS;
}
