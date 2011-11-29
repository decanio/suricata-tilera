/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 */

#define COMPRESS_ALPHABET

#define SC_ACC_STATE_TYPE_U8 uint8_t
#define SC_ACC_STATE_TYPE_U16 uint16_t
#define SC_ACC_STATE_TYPE_U32 uint32_t

typedef struct SCACCPattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags decribing the pattern */
    uint8_t flags;
    /* holds the original pattern that was added */
    uint8_t *original_pat;
    /* case sensitive */
    uint8_t *cs;
    /* case INsensitive */
    uint8_t *ci;
    /* pattern id */
    uint32_t id;

    struct SCACCPattern_ *next;
} SCACCPattern;

typedef struct SCACCPatternList_ {
    uint8_t *cs;
    uint16_t patlen;
    uint16_t case_state;
} SCACCPatternList;

typedef struct SCACCOutputTable_ {
    /* list of pattern sids */
    uint32_t *pids;
    /* no of entries we have in pids */
    uint32_t no_of_entries;
} SCACCOutputTable;

#ifdef COMPRESS_ALPHABET
#define ALPHABET_SIZE	(256 - ('Z'-'A'+1))
#else
#define ALPHABET_SIZE	256
#endif

typedef struct state_table_hdr {
    struct state_table_hdr *next;
    int state_count;
    size_t size;
    uint16_t entries;
    uint8_t alpha_map[ALPHABET_SIZE];
} state_table_hdr_t;

typedef struct state_table8 {
    state_table_hdr_t hdr;
    SC_ACC_STATE_TYPE_U8 u8[];
} state_table8_t;

typedef struct state_table16 {
    state_table_hdr_t hdr;
    SC_ACC_STATE_TYPE_U16 u16[];
} state_table16_t;

typedef struct state_table32 {
    state_table_hdr_t hdr;
    SC_ACC_STATE_TYPE_U32 u32[];
} state_table32_t;

#ifdef __tile__
/* Reordered for Tilera cache */
typedef struct SCACCCtx_ {
    /* This stuff is used at search time */

    SC_ACC_STATE_TYPE_U8 *state_table_m8;
    SC_ACC_STATE_TYPE_U16 *state_table_m16;
    SC_ACC_STATE_TYPE_U32 *state_table_m32;

    /* the all important memory hungry state_table */
    SC_ACC_STATE_TYPE_U8 (*state_table_u8)[ALPHABET_SIZE];
    /* the all important memory hungry state_table */
    SC_ACC_STATE_TYPE_U16 (*state_table_u16)[ALPHABET_SIZE];
    /* the all important memory hungry state_table */
    SC_ACC_STATE_TYPE_U32 (*state_table_u32)[ALPHABET_SIZE];

    SCACCOutputTable *output_table;
    SCACCPatternList *pid_pat_list;

    /* the stuff below is only used at initialization time */

    /* hash used during ctx initialization */
    SCACCPattern **init_hash;

    /* pattern arrays.  We need this only during the goto table creation phase */
    SCACCPattern **parray;

    /* no of states used by ac */
    uint32_t state_count;

    /* goto_table, failure table and output table.  Needed to create state_table.
     * Will be freed, once we have created the state_table */
    int32_t (*goto_table)[256];
    int32_t *failure_table;

    /* the size of each state */
    uint16_t single_state_size;
    uint16_t max_pat_id;
} SCACCCtx;
#else
typedef struct SCACCCtx_ {
    /* hash used during ctx initialization */
    SCACCPattern **init_hash;

    /* pattern arrays.  We need this only during the goto table creation phase */
    SCACCPattern **parray;

    /* no of states used by ac */
    uint32_t state_count;
    /* the all important memory hungry state_table */
    SC_ACC_STATE_TYPE_U8 (*state_table_u8)[ALPHABET_SIZE];
    /* the all important memory hungry state_table */
    SC_ACC_STATE_TYPE_U16 (*state_table_u16)[ALPHABET_SIZE];
    /* the all important memory hungry state_table */
    SC_ACC_STATE_TYPE_U32 (*state_table_u32)[ALPHABET_SIZE];

    SC_ACC_STATE_TYPE_U8 *state_table_m8;
    SC_ACC_STATE_TYPE_U16 *state_table_m16;
    SC_ACC_STATE_TYPE_U32 *state_table_m32;

    /* goto_table, failure table and output table.  Needed to create state_table.
     * Will be freed, once we have created the state_table */
    int32_t (*goto_table)[256];
    int32_t *failure_table;
    SCACCOutputTable *output_table;
    SCACCPatternList *pid_pat_list;

    /* the size of each state */
    uint16_t single_state_size;
    uint16_t max_pat_id;

} SCACCCtx;
#endif

typedef struct SCACCThreadCtx_ {
    /* the total calls we make to the search function */
    uint32_t total_calls;
    /* the total patterns that we ended up matching against */
    uint64_t total_matches;
} SCACCThreadCtx;

void MpmACCRegister(void);
